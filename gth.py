#!/usr/bin/env python3
# 🕵️  GTH3 — GitHub Threat Hunter (audit/IR) — Threat Engine (SOC)
# Single-command CLI: python GTH3_ThreatEngine_FIXED2.py TARGET [options...]
# by Neurone4444 (patched)

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Iterable

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


console = Console()


# -----------------------------
# Helpers
# -----------------------------

def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def truncate(s: str, n: int = 200) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ")
    return s[:n] + ("…" if len(s) > n else "")

def redact_value(value: str, keep: int = 4) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= keep * 2:
        return "*" * len(v)
    return v[:keep] + "*" * (len(v) - keep * 2) + v[-keep:]

def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    nontext = 0
    sample = data[:4096]
    for b in sample:
        if b in (9, 10, 13):
            continue
        if b < 32 or b > 126:
            nontext += 1
    return (nontext / max(1, len(sample))) > 0.30


def shannon_entropy(s: str) -> float:
    """Shannon entropy per stimare 'casualità' di una stringa."""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * log2(p)
    return ent

_HASH_HEX_RE = re.compile(r"(?i)^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_UUID_RE = re.compile(r"(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

def looks_like_benign_hash_or_uuid(s: str) -> bool:
    ss = (s or "").strip()
    if _HASH_HEX_RE.fullmatch(ss):
        return True
    if _UUID_RE.fullmatch(ss):
        return True
    return False

def is_hex_string(s: str, min_len: int = 24) -> bool:
    ss = (s or "").strip()
    if len(ss) < min_len:
        return False
    return bool(re.fullmatch(r"(?i)[a-f0-9]{%d,}" % min_len, ss))



def parse_dt_utc(s: str) -> Optional[datetime]:
    """Parse ISO-8601 datetime from GitHub fields; normalizes to UTC tz-aware."""
    if not s:
        return None
    ss = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(ss)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# -----------------------------
# Models
# -----------------------------

@dataclass
class TargetInfo:
    login: str
    type: str
    bio: str = ""
    location: str = ""
    company: str = ""
    email: str = ""
    public_repos: int = 0
    followers: int = 0
    following: int = 0
    created_at: str = ""
    html_url: str = ""

@dataclass
class RepoInfo:
    full_name: str
    name: str
    private: bool
    fork: bool
    stargazers_count: int
    forks_count: int
    language: str
    pushed_at: str
    created_at: str
    html_url: str
    default_branch: str

@dataclass
class EmailHit:
    email: str
    name: str
    role: str
    repo: str
    sha: str
    date: str
    message: str

@dataclass
class SecretHit:
    kind: str
    repo: str
    path: str
    line: int
    match: str
    context: str
    confidence: int
    score: int = 0
    severity: str = ""
    is_test: bool = False
    fingerprint: str = ""
    note: str = ""


# -----------------------------
# GitHub Client
# -----------------------------

class GitHubClient:
    def __init__(self, token: str = "", timeout: int = 25):
        self.base = "https://api.github.com"
        self.session = requests.Session()
        self.timeout = timeout
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "GTH-ThreatHunter/3.0",
        }
        if token:
            headers["Authorization"] = f"token {token}"
        self.session.headers.update(headers)

    def _req(self, method: str, url: str, **kwargs):
        """HTTP request with simple retry + rate-limit + transient error handling.

        Returns a `requests.Response`. On repeated network errors, returns a synthetic
        Response with status_code=599 so callers can treat it as a non-200.
        """
        timeout = kwargs.pop("timeout", self.timeout)
        last_exc: Optional[Exception] = None

        for attempt in range(1, 6):
            try:
                r = self.session.request(method, url, timeout=timeout, **kwargs)
            except requests.exceptions.RequestException as e:
                last_exc = e
                sleep_s = min(2 ** (attempt - 1), 10)
                console.print(
                    f"[yellow]⚠️  Network error ({type(e).__name__}) on {url} — retry {attempt}/5 in {sleep_s}s[/yellow]"
                )
                time.sleep(sleep_s)
                continue

            if r.status_code == 403 and "rate limit" in (r.text or "").lower():
                reset = r.headers.get("X-RateLimit-Reset")
                if reset:
                    sleep_s = max(1, int(reset) - int(time.time()) + 1)
                    console.print(f"[yellow]⏳ Rate limit hit, sleeping {min(sleep_s,60)}s[/yellow]")
                    time.sleep(min(sleep_s, 60))
                    continue
            return r

        resp = requests.Response()
        resp.status_code = 599
        msg = f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown error"
        resp._content = msg.encode("utf-8", errors="ignore")
        resp.url = url
        resp.headers = {}
        return resp

    def rate_limit(self) -> Tuple[int, int, str]:
        r = self._req("GET", f"{self.base}/rate_limit")
        if r.status_code != 200:
            return 0, 0, "unknown"
        data = r.json()
        core = data.get("resources", {}).get("core", {})
        remaining = int(core.get("remaining", 0))
        limit = int(core.get("limit", 0))
        reset_ts = int(core.get("reset", 0))
        reset_str = datetime.fromtimestamp(reset_ts).strftime("%H:%M:%S") if reset_ts else "unknown"
        return remaining, limit, reset_str

    def whoami(self) -> Optional[str]:
        r = self._req("GET", f"{self.base}/user")
        if r.status_code != 200:
            return None
        return (r.json() or {}).get("login") or None

    def get_user_or_org(self, login: str) -> Optional[TargetInfo]:
        r = self._req("GET", f"{self.base}/users/{login}")
        if r.status_code != 200:
            return None
        u = r.json()
        return TargetInfo(
            login=u.get("login", login),
            type=u.get("type", ""),
            bio=u.get("bio") or "",
            location=u.get("location") or "",
            company=u.get("company") or "",
            email=u.get("email") or "",
            public_repos=int(u.get("public_repos") or 0),
            followers=int(u.get("followers") or 0),
            following=int(u.get("following") or 0),
            created_at=(u.get("created_at") or "")[:10],
            html_url=u.get("html_url") or "",
        )

    def list_repos(self, login: str, is_org: bool, include_forks: bool, max_repos: int) -> List[RepoInfo]:
        repos: List[RepoInfo] = []
        page = 1
        per_page = 100
        endpoint = f"{self.base}/orgs/{login}/repos" if is_org else f"{self.base}/users/{login}/repos"
        params = {"per_page": per_page, "page": page, "sort": "pushed", "direction": "desc", "type": "all"}
        while len(repos) < max_repos:
            params["page"] = page
            r = self._req("GET", endpoint, params=params)
            if r.status_code != 200:
                break
            batch = r.json() or []
            if not batch:
                break
            for x in batch:
                if (not include_forks) and bool(x.get("fork")):
                    continue
                repos.append(RepoInfo(
                    full_name=x.get("full_name", ""),
                    name=x.get("name", ""),
                    private=bool(x.get("private")),
                    fork=bool(x.get("fork")),
                    stargazers_count=int(x.get("stargazers_count") or 0),
                    forks_count=int(x.get("forks_count") or 0),
                    language=x.get("language") or "—",
                    pushed_at=(x.get("pushed_at") or "")[:10],
                    created_at=(x.get("created_at") or ""),
                    html_url=x.get("html_url") or "",
                    default_branch=x.get("default_branch") or "main",
                ))
                if len(repos) >= max_repos:
                    break
            page += 1
        return repos

    def list_commits(self, owner: str, repo: str, max_commits: int, path: str = "") -> List[dict]:
        commits: List[dict] = []
        page = 1
        per_page = 100
        params = {"per_page": per_page, "page": page}
        if path:
            params["path"] = path
        while len(commits) < max_commits:
            params["page"] = page
            r = self._req("GET", f"{self.base}/repos/{owner}/{repo}/commits", params=params)
            if r.status_code != 200:
                break
            batch = r.json() or []
            if not batch:
                break
            commits.extend(batch)
            page += 1
        return commits[:max_commits]

    def contents(self, owner: str, repo: str, path: str, ref: str) -> Optional[List[dict]]:
        url = f"{self.base}/repos/{owner}/{repo}/contents/{path}".rstrip("/")
        params = {"ref": ref} if ref else None
        r = self._req("GET", url, params=params)
        if r.status_code != 200:
            return None
        j = r.json()
        if isinstance(j, list):
            return j
        return [j]

    def download_file(self, download_url: str) -> Optional[bytes]:
        """Download a raw file with retries; never raises on timeout."""
        for attempt in range(1, 5):
            try:
                r = self._req("GET", download_url, timeout=(10, max(15, self.timeout)))
                if r.status_code != 200:
                    return None
                return r.content
            except requests.exceptions.RequestException as e:
                sleep_s = min(2 ** (attempt - 1), 8)
                console.print(f"[yellow]⚠️  Download error ({type(e).__name__}) — retry {attempt}/4 in {sleep_s}s[/yellow]")
                time.sleep(sleep_s)
                continue
        return None

    def code_search(self, q: str, pages: int = 1) -> List[dict]:
        out: List[dict] = []
        for page in range(1, pages + 1):
            r = self._req("GET", f"{self.base}/search/code", params={"q": q, "per_page": 30, "page": page})
            if r.status_code != 200:
                break
            data = r.json() or {}
            items = data.get("items") or []
            out.extend(items)
            if len(items) < 30:
                break
        return out


# -----------------------------
# Threat / scoring utilities
# -----------------------------

def repo_risk(repo: RepoInfo) -> int:
    risk = 0
    created = parse_dt_utc(repo.created_at)
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < 30:
            risk += 25
        elif age_days < 90:
            risk += 15

    pushed = parse_dt_utc(repo.pushed_at)
    if pushed:
        pd = (datetime.now(timezone.utc) - pushed).days
        if pd < 7:
            risk += 15
        elif pd < 30:
            risk += 8

    if repo.stargazers_count < 5:
        risk += 10
    elif repo.stargazers_count < 50:
        risk += 5

    if repo.fork:
        risk += 10

    return min(100, risk)

def contributor_anomaly_from_commits(commits: List[dict]) -> str:
    recent_cut = datetime.now(timezone.utc).date().toordinal() - 30
    uniq_recent = set()
    for c in commits:
        commit = c.get("commit") or {}
        author = (commit.get("author") or {})
        dt = (author.get("date") or "")[:10]
        email = (author.get("email") or "").lower()
        try:
            d = datetime.fromisoformat(dt).date().toordinal()
        except Exception:
            continue
        if d >= recent_cut and email:
            uniq_recent.add(email)
    if len(uniq_recent) >= 8:
        return "commit_spike_30d"
    return ""

def drift_last_seen(client: GitHubClient, repo_full: str, path: str, pages: int, per_page: int = 100) -> Tuple[str, int]:
    owner, repo = repo_full.split("/", 1)
    max_commits = pages * per_page
    commits = client.list_commits(owner, repo, max_commits=max_commits, path=path)
    if not commits:
        return "", -1
    commit = commits[0].get("commit") or {}
    author = commit.get("author") or {}
    dt = (author.get("date") or "")[:10]
    if not dt:
        return "", -1
    try:
        d = datetime.fromisoformat(dt).date()
        days = (datetime.now(timezone.utc).date() - d).days
        return dt, days
    except Exception:
        return dt, -1


# -----------------------------
# Scanners
# -----------------------------

class EmailExtractor:
    EMAIL_RE = re.compile(r"""([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,})""")

    def extract_from_commits(self, repo_full: str, commits: List[dict], hide_noreply: bool = False) -> List[EmailHit]:
        hits: List[EmailHit] = []
        for c in commits:
            sha = (c.get("sha") or "")[:8]
            commit = c.get("commit") or {}
            author = commit.get("author") or {}
            committer = commit.get("committer") or {}
            msg = (commit.get("message") or "").strip()
            date = (author.get("date") or committer.get("date") or "")[:10]

            a = commit.get("author") or {}
            email = (a.get("email") or "").strip()
            name = (a.get("name") or "").strip()
            if email and self.EMAIL_RE.fullmatch(email):
                if hide_noreply and "noreply.github.com" in email:
                    pass
                else:
                    hits.append(EmailHit(email=email, name=name or "—", role="author", repo=repo_full, sha=sha, date=date, message=truncate(msg, 180)))

            cm = commit.get("committer") or {}
            cemail = (cm.get("email") or "").strip()
            cname = (cm.get("name") or "").strip()
            if cemail and self.EMAIL_RE.fullmatch(cemail):
                if hide_noreply and ("noreply.github.com" in cemail or cemail == "noreply@github.com"):
                    pass
                else:
                    hits.append(EmailHit(email=cemail, name=cname or "—", role="committer", repo=repo_full, sha=sha, date=date, message=truncate(msg, 180)))
        return hits


class SecretScanner:
    RE_FAKE = re.compile(r'''(?m)^\s*(FAKE_SECRET\[[A-Z0-9_-]{2,}\])\s*=\s*['"]?([A-Za-z0-9._\-]{8,})['"]?\s*$''')
    RE_KEYWORD = re.compile(
        r'''(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-\/\+=\.]{8,})['"]?'''
    )
    RE_JWT = re.compile(r'''\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b''')
    RE_PRIVKEY = re.compile(r'''-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----''')

    VALIDATED = [
        ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}\b"), 85, "GitHub classic token-like (formato)"),
        ("GITHUB_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), 85, "GitHub fine-grained PAT-like (formato)"),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 80, "Slack token-like (formato)"),
        ("STRIPE_SECRET", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"), 80, "Stripe key-like (formato)"),
        ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 80, "Google API key-like (formato)"),
        ("TELEGRAM_BOT_TOKEN", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"), 75, "Telegram bot token-like (formato)"),
        ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 80, "SendGrid key-like (formato)"),
        ("TWILIO_ACCOUNT_SID", re.compile(r"\bAC[a-f0-9]{32}\b", re.IGNORECASE), 70, "Twilio Account SID-like (formato)"),
        ("TWILIO_API_KEY_SID", re.compile(r"\bSK[a-f0-9]{32}\b", re.IGNORECASE), 70, "Twilio API Key SID-like (formato)"),
        ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 80, "AWS Access Key ID-like (formato)"),
    ]

    RE_ENTROPY_CAND = re.compile(r'''(?P<s>[A-Za-z0-9_\-\/\+=\.]{20,200})''')

    def __init__(self, redact: bool = True, entropy_threshold: float = 4.85, enable_entropy: bool = True):
        self.redact = redact
        self.entropy_threshold = entropy_threshold
        self.enable_entropy = enable_entropy

    def scan_text(self, repo: str, path: str, text: str) -> List[SecretHit]:
        hits: List[SecretHit] = []
        lines = text.splitlines()
        path_l = (path or "").lower()
        repo_l = (repo or "").lower()

        for i, line in enumerate(lines, start=1):
            fm = self.RE_FAKE.search(line)
            if fm:
                raw = f"{fm.group(1)}={fm.group(2)}"
                shown = redact_value(raw) if self.redact else raw
                hits.append(SecretHit(
                    kind="FAKE_SECRET",
                    repo=repo,
                    path=path,
                    line=i,
                    match=shown,
                    context=truncate(line, 220),
                    confidence=95,
                    note="Marker di test (consigliato).",
                ))

            for kind, rx, conf, note in self.VALIDATED:
                vm = rx.search(line)
                if vm:
                    raw = vm.group(0)
                    shown = redact_value(raw) if self.redact else raw
                    hits.append(SecretHit(
                        kind=kind,
                        repo=repo,
                        path=path,
                        line=i,
                        match=shown,
                        context=truncate(line, 220),
                        confidence=conf,
                        note=note,
                    ))

            for km in self.RE_KEYWORD.finditer(line):
                key = km.group(1)
                val = km.group(2)
                raw = f"{key}={val}"
                shown = redact_value(raw) if self.redact else raw
                hits.append(SecretHit(
                    kind="KEYWORD_SECRET",
                    repo=repo,
                    path=path,
                    line=i,
                    match=shown,
                    context=truncate(line, 220),
                    confidence=70,
                    note="Assegnazione sospetta (keyword-based).",
                ))

            jm = self.RE_JWT.search(line)
            if jm:
                raw = jm.group(0)
                shown = redact_value(raw) if self.redact else raw
                hits.append(SecretHit(
                    kind="JWT",
                    repo=repo,
                    path=path,
                    line=i,
                    match=shown,
                    context=truncate(line, 220),
                    confidence=65,
                    note="JWT-like token (indicator).",
                ))

            if self.RE_PRIVKEY.search(line):
                hits.append(SecretHit(
                    kind="PRIVATE_KEY_BLOCK",
                    repo=repo,
                    path=path,
                    line=i,
                    match="-----BEGIN … KEY-----",
                    context=truncate(line, 220),
                    confidence=90,
                    note="Blocco chiave privata (indicator).",
                ))

            if not self.enable_entropy:
                continue

            if any(seg in path_l for seg in ["/dist/", "/build/", ".min.", "/vendor/"]):
                continue

            if "advisory-database" in repo_l and path_l.endswith((".json", ".yml", ".yaml")):
                continue

            ll = line.lower()
            if any(k in ll for k in ["sha256", "sha1", "md5", "checksum", "digest", '"hash"', "'hash'", "cve-", "ghsa-"]):
                continue

            for em in self.RE_ENTROPY_CAND.finditer(line):
                s = em.group("s")
                if len(s) < 28:
                    continue
                if looks_like_benign_hash_or_uuid(s) or is_hex_string(s, 28):
                    continue
                if re.search(r"\d{10,}", s):
                    continue
                if len(s) >= 32 and len(set(s)) <= 8:
                    continue

                ent = shannon_entropy(s)
                if ent >= self.entropy_threshold:
                    shown = redact_value(s) if self.redact else s
                    hits.append(SecretHit(
                        kind="HIGH_ENTROPY",
                        repo=repo,
                        path=path,
                        line=i,
                        match=shown,
                        context=truncate(line, 220),
                        confidence=58,
                        note=f"Stringa ad alta entropia (H={ent:.2f}) senza keyword.",
                    ))

        return hits

# -----------------------------
# Repo walker (Contents API)
# -----------------------------

SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav",
}

def should_skip_path(path: str) -> bool:
    p = path.lower()
    _, ext = os.path.splitext(p)
    if ext in SKIP_EXT:
        return True
    if any(seg in p for seg in ["/node_modules/", "/dist/", "/build/", "/.git/", "/.venv/", "/venv/"]):
        return True
    return False

def walk_repo_files(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    max_files: int,
    max_depth: int,
) -> Iterable[Tuple[str, str]]:
    stack: List[Tuple[str, int]] = [("", 0)]
    seen = 0

    while stack and seen < max_files:
        path, depth = stack.pop()
        if depth > max_depth:
            continue

        items = client.contents(owner, repo, path, ref=ref)
        if not items:
            continue

        for it in items:
            it_type = it.get("type")
            it_path = it.get("path") or ""
            if not it_path:
                continue

            if it_type == "dir":
                stack.append((it_path, depth + 1))
                continue

            if it_type == "file":
                if should_skip_path(it_path):
                    continue
                dl = it.get("download_url")
                if not dl:
                    continue
                yield it_path, dl
                seen += 1
                if seen >= max_files:
                    break


# -----------------------------
# UI printing
# -----------------------------

def print_banner():
    console.print(Panel.fit(
        "[bold]🕵️  GTH 3.0[/bold]\n[dim]GitHub Threat Hunter — Threat Engine (SOC)\nby Neurone4444[/dim]",
        border_style="cyan"
    ))

def print_target_info(t: TargetInfo):
    tbl = Table(title="📋 Target Info", box=box.SIMPLE, show_lines=False)
    tbl.add_column("Field", style="dim", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("👤", f"{t.login} ({t.type})")
    tbl.add_row("Bio", t.bio or "—")
    tbl.add_row("Location", t.location or "—")
    tbl.add_row("Company", t.company or "—")
    tbl.add_row("Public email", t.email or "(hidden)")
    tbl.add_row("Repos", str(t.public_repos))
    tbl.add_row("Followers", str(t.followers))
    tbl.add_row("Following", str(t.following))
    tbl.add_row("Created", t.created_at or "—")
    tbl.add_row("Profile", t.html_url or "—")
    console.print(tbl)

def print_repos_table(repos: List[RepoInfo]):
    tbl = Table(title="📁 Repo analizzati", box=box.SIMPLE_HEAVY)
    tbl.add_column("Repo", no_wrap=True)
    tbl.add_column("⭐", justify="right")
    tbl.add_column("🍴", justify="right")
    tbl.add_column("Lingua")
    tbl.add_column("Pushed", no_wrap=True)
    for r in repos:
        tbl.add_row(r.name, str(r.stargazers_count), str(r.forks_count), r.language or "—", r.pushed_at or "—")
    console.print(tbl)

def print_emails_table(emails: List[EmailHit], max_rows: int = 60):
    if not emails:
        console.print("[dim]Nessuna email trovata.[/dim]")
        return
    tbl = Table(title=f"📧 Email trovate ({len(emails)} hit)", box=box.SIMPLE_HEAVY)
    tbl.add_column("Email", no_wrap=True)
    tbl.add_column("Nome", no_wrap=True)
    tbl.add_column("Ruolo", no_wrap=True)
    tbl.add_column("Repo", no_wrap=True)
    tbl.add_column("Data", no_wrap=True)
    for e in emails[:max_rows]:
        tbl.add_row(e.email, e.name or "—", e.role, e.repo, e.date or "—")
    if len(emails) > max_rows:
        console.print(f"[dim]… +{len(emails) - max_rows} altri[/dim]")
    console.print(tbl)

def print_secrets_table(secrets: List[SecretHit], hide_tests: bool, max_rows: int = 120):
    if hide_tests:
        secrets = [s for s in secrets if not s.is_test]

    if not secrets:
        console.print("[green]✅ Nessun segreto ad alta confidenza trovato[/green]")
        console.print("[dim]Nessun finding rilevante.[/dim]")
        return

    tbl = Table(title=f"🔑 Findings ({len(secrets)} hit) — ordinati per score", box=box.SIMPLE_HEAVY)
    tbl.add_column("Sev", no_wrap=True)
    tbl.add_column("Score", justify="right", no_wrap=True)
    tbl.add_column("Tipo", no_wrap=True)
    tbl.add_column("Repo", no_wrap=True)
    tbl.add_column("Path")
    tbl.add_column("Line", justify="right", no_wrap=True)
    tbl.add_column("Match")
    tbl.add_column("Test", no_wrap=True)

    for s in secrets[:max_rows]:
        tbl.add_row(
            s.severity or "—",
            str(s.score or 0),
            s.kind,
            s.repo,
            s.path,
            str(s.line),
            truncate(s.match, 70),
            "Y" if s.is_test else "—",
        )

    if len(secrets) > max_rows:
        console.print(f"[dim]… +{len(secrets) - max_rows} altri[/dim]")
    console.print(tbl)


# -----------------------------
# Main logic
# -----------------------------

def score_secret(hit: SecretHit) -> SecretHit:
    path_l = (hit.path or "").lower()
    ctx_l = (hit.context or "").lower()

    is_test = any(x in path_l for x in [
        "/test", "tests/", "fixtures", "example", "examples", "sample", "docs/", "documentation", ".env.example"
    ]) or any(x in ctx_l for x in ["example", "dummy", "test key", "self-signed", "for testing"])

    base = hit.confidence
    score = base

    if hit.kind == "PRIVATE_KEY_BLOCK":
        score = 95

    elif hit.kind == "FAKE_SECRET":
        score = 10

    elif hit.kind in (
        "GITHUB_TOKEN", "GITHUB_PAT", "SLACK_TOKEN", "STRIPE_SECRET",
        "GOOGLE_API_KEY", "TELEGRAM_BOT_TOKEN", "SENDGRID_KEY",
        "TWILIO_ACCOUNT_SID", "TWILIO_API_KEY_SID", "AWS_ACCESS_KEY_ID"
    ):
        score = 85

    elif hit.kind == "HIGH_ENTROPY":
        score = 60

    elif hit.kind in ("JWT", "KEYWORD_SECRET"):
        score = 70

    if is_test:
        score = max(5, score - 35)

    severity = "LOW"
    if score >= 90:
        severity = "CRITICAL"
    elif score >= 75:
        severity = "HIGH"
    elif score >= 55:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    fp_src = f"{hit.kind}|{hit.repo}|{hit.path}|{hit.line}|{hit.context}"
    fp = hashlib.sha256(fp_src.encode("utf-8", errors="ignore")).hexdigest()[:12]

    hit.is_test = is_test
    hit.score = score
    hit.severity = severity
    hit.fingerprint = fp
    return hit

def run(args: argparse.Namespace) -> int:
    print_banner()

    client = GitHubClient(token=args.token, timeout=args.timeout)
    rem, lim, reset = client.rate_limit()
    console.print(f"🔑 Rate limit: {rem}/{lim} (reset {reset})\n")

    if args.whoami:
        me = client.whoami()
        console.print(f"👤 Token user: {me or '(unknown)'}")
        return 0

    console.print(f"🔍 Ricerca target: [bold]{args.target}[/bold]...")
    tinfo = client.get_user_or_org(args.target)
    if not tinfo:
        console.print("[red]Target non trovato o errore API.[/red]")
        return 2

    is_org = (tinfo.type.lower() == "organization")
    print_target_info(tinfo)
    console.print()

    console.print(f"📁 Recupero repo (max {args.max_repos})...")
    repos = client.list_repos(args.target, is_org=is_org, include_forks=args.include_forks, max_repos=args.max_repos)
    console.print(f"  ✅ {len(repos)} repo trovati")
    print_repos_table(repos)
    console.print()

    extractor = EmailExtractor()
    all_emails: List[EmailHit] = []

    if not args.only_secrets:
        console.print("📧 Estrazione email dai commit...")
        for r in repos:
            owner, repo_name = r.full_name.split("/", 1)
            commits = client.list_commits(owner, repo_name, max_commits=args.max_commits)
            all_emails.extend(extractor.extract_from_commits(r.full_name, commits, hide_noreply=True))

        seen = set()
        uniq_emails: List[EmailHit] = []
        for e in all_emails:
            k = (e.email.lower(), e.repo, e.role)
            if k in seen:
                continue
            seen.add(k)
            uniq_emails.append(e)

        console.print(f"  ✅ {len({e.email.lower() for e in uniq_emails})} email uniche trovate")
        if len(uniq_emails) > 60:
            console.print(f"[dim]… +{len(uniq_emails)-60} altri[/dim]")
        print_emails_table(uniq_emails, max_rows=60)
    else:
        uniq_emails = []

    secrets: List[SecretHit] = []
    if args.secrets:
        console.print("🔑 Secret scanning (repo files)...")
        scanner = SecretScanner(redact=args.redact, entropy_threshold=args.entropy_threshold, enable_entropy=args.enable_entropy)

        for r in repos:
            owner, repo_name = r.full_name.split("/", 1)
            for path, dl in walk_repo_files(
                client=client,
                owner=owner,
                repo=repo_name,
                ref=r.default_branch,
                max_files=args.max_files,
                max_depth=args.max_depth,
            ):
                data = client.download_file(dl)
                if not data:
                    continue
                if is_probably_binary(data):
                    continue
                if len(data) > args.max_file_bytes:
                    continue

                text = data.decode("utf-8", errors="ignore")
                hits = scanner.scan_text(repo=r.full_name, path=path, text=text)
                for h in hits:
                    secrets.append(score_secret(h))

        dedup: Dict[str, SecretHit] = {}
        for h in secrets:
            fp = h.fingerprint or f"{h.kind}|{h.repo}|{h.path}|{h.line}"
            dedup[fp] = h
        secrets = list(dedup.values())
        secrets.sort(key=lambda x: (-x.score, -x.confidence, x.repo, x.path, x.line))

        high = [s for s in secrets if s.score >= 75 and (not s.is_test or not args.hide_tests)]
        if not high:
            console.print("✅ Nessun segreto ad alta confidenza trovato")
            console.print("[dim]Nessun finding rilevante.[/dim]")
        else:
            print_secrets_table(secrets, hide_tests=args.hide_tests)

    safe_mkdir(args.out_dir)
    stamp = now_iso().replace(":", "").replace("-", "")
    base = os.path.join(args.out_dir, f"gth_{args.target}_{stamp}")

    report = {
        "generated_at": now_iso(),
        "target": asdict(tinfo),
        "repos": [asdict(r) for r in repos],
        "emails": [asdict(e) for e in uniq_emails],
        "secrets": [asdict(s) for s in secrets],
        "settings": {
            "mode": args.mode,
            "only_secrets": args.only_secrets,
            "hide_tests": args.hide_tests,
        },
    }

    if args.json_out:
        json_path = base + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        console.print(f"\n📄 JSON: {json_path}")

    if args.csv_out and uniq_emails:
        csv_path = base + "_emails.csv"
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["email", "name", "role", "repo", "sha", "date", "message"])
            for e in uniq_emails:
                w.writerow([e.email, e.name, e.role, e.repo, e.sha, e.date, e.message])
        console.print(f"📊 Emails CSV: {csv_path}")

    if args.network:
        html_path = base + ".html"
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GTH Report - {args.target}</title>
<style>body{{font-family:system-ui,Segoe UI,Arial;margin:24px}} code{{background:#f2f2f2;padding:2px 6px;border-radius:6px}}</style>
</head><body>
<h1>GTH Report — {args.target}</h1>
<p><b>Generated:</b> {report["generated_at"]}</p>
<ul>
<li>Repos analyzed: <code>{len(repos)}</code></li>
<li>Email hits: <code>{len(uniq_emails)}</code></li>
<li>Secret hits: <code>{len(secrets)}</code></li>
</ul>
<p>Use JSON for full details.</p>
</body></html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"🌐 HTML: {html_path}")

        if args.open_browser:
            try:
                import webbrowser
                webbrowser.open(f"file:///{os.path.abspath(html_path)}")
            except Exception:
                pass

    rem2, lim2, reset2 = client.rate_limit()
    console.print(f"\n🔑 Rate limit finale: {rem2}/{lim2} (reset {reset2})")
    console.print("\n✅ GTH completato! 🎯")
    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="GTH3_ThreatEngine_FINAL.py",
        description="🕵️  GTH — GitHub Threat Hunter — Threat Engine (SOC).",
    )
    p.add_argument("target", help="Username o organizzazione GitHub (es: psf)")
    p.add_argument("--token", "-t", default="", help="GitHub token (aumenta rate limit)")
    p.add_argument("--whoami", action="store_true", help="Mostra l'utente associato al token e termina")
    p.add_argument("--mode", choices=["fast", "balanced", "deep"], default="balanced", help="Preset di performance")
    p.add_argument("--max-repos", "-r", type=int, default=10, help="Numero max repo da analizzare")
    p.add_argument("--max-commits", type=int, default=30, help="Numero max commit per repo (email)")
    p.add_argument("--max-files", type=int, default=120, help="Numero max file da scansionare per repo (secret scan)")
    p.add_argument("--max-depth", type=int, default=6, help="Profondità ricorsione directory (contents API)")
    p.add_argument("--max-file-bytes", type=int, default=1_000_000, help="Dimensione max file scaricato (bytes)")
    p.add_argument("--include-forks", action="store_true", help="Include anche fork")
    p.add_argument("--only-secrets", action="store_true", help="Salta email, fa solo secret scanning")

    p.add_argument("--secrets", dest="secrets", action="store_true", help="Abilita secret scanning su file repo")
    p.add_argument("--no-secrets", dest="secrets", action="store_false", help="Disabilita secret scanning")
    p.set_defaults(secrets=True)

    p.add_argument("--hide-tests", dest="hide_tests", action="store_true", help="Nasconde findings di test/docs/examples")
    p.add_argument("--no-hide-tests", dest="hide_tests", action="store_false", help="Mostra anche findings di test")
    p.set_defaults(hide_tests=False)

    p.add_argument("--redact", dest="redact", action="store_true", help="Redige match in output")
    p.add_argument("--no-redact", dest="redact", action="store_false", help="Stampa match in chiaro (sconsigliato)")
    p.set_defaults(redact=True)
    p.add_argument("--entropy-threshold", type=float, default=4.85, help="Soglia entropy per HIGH_ENTROPY (default: 4.85, più preciso)")
    p.add_argument("--no-entropy", dest="enable_entropy", action="store_false", help="Disabilita entropy detection (riduce rumore)")
    p.add_argument("--entropy", dest="enable_entropy", action="store_true", help="Abilita entropy detection")
    p.set_defaults(enable_entropy=True)

    p.add_argument("--network", dest="network", action="store_true", help="Genera HTML report leggero")
    p.add_argument("--no-network", dest="network", action="store_false", help="No HTML report")
    p.set_defaults(network=True)

    p.add_argument("--json", dest="json_out", action="store_true", help="Esporta report JSON")
    p.add_argument("--no-json", dest="json_out", action="store_false", help="No JSON")
    p.set_defaults(json_out=True)

    p.add_argument("--csv", dest="csv_out", action="store_true", help="Esporta CSV email")
    p.add_argument("--no-csv", dest="csv_out", action="store_false", help="No CSV")
    p.set_defaults(csv_out=True)

    p.add_argument("--open", dest="open_browser", action="store_true", help="Apri HTML nel browser")
    p.add_argument("--no-open", dest="open_browser", action="store_false", help="Non aprire il browser")
    p.set_defaults(open_browser=True)

    p.add_argument("--out-dir", default="output", help="Directory output")
    p.add_argument("--timeout", type=int, default=25, help="Timeout HTTP (s)")

    return p


def main() -> int:
    p = build_argparser()
    args = p.parse_args()

    try:
        return run(args)
    except KeyboardInterrupt:
        console.print("\n[red]Interrotto.[/red]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
# GTH — GitHub Threat Hunter

Standalone GitHub OSINT scanner for fast triage on GitHub users/organizations, with SOC-friendly JSON/HTML reports.

## Overview

GTH (GitHub Threat Hunter) is a lightweight standalone tool for OSINT-based technical analysis of GitHub users and organizations.

It supports:

- Repository enumeration (controlled sampling)
- Commit email extraction
- Secret pattern detection
- Optional entropy-based heuristics
- Structured JSON / HTML reporting

Designed for investigative, security hygiene, and blue-team triage workflows.

## Features

- Target lookup (User / Organization)
- Controlled repository scanning (`max-repos`, `max-files`, `max-depth`)
- Commit email extraction
- Secret detection (pattern/heuristic-based):
  - GitHub token patterns
  - AWS Access Key IDs
  - Slack tokens
  - Stripe secrets
  - Keyword-based secrets
  - Optional entropy detection
- JSON + HTML output reports
- Adjustable noise control (strict / balanced)

## Requirements

- Python 3.9+
- GitHub Personal Access Token (PAT)

## Security note (important)

- Treat your GitHub PAT as a secret. Never paste it into screenshots, logs, or public issues.
- GTH does not validate secrets (it detects patterns/heuristics). Always triage findings in context.

## Limitations

- Scanning is sampled/limited by `max-repos`, `max-files`, and `max-depth`. "No findings" does not guarantee a target is clean.
- Results depend on repository visibility, branch selection, and GitHub API behavior/rate limits.

## Setting GitHub Token (Windows CMD)

```cmd
set "GITHUB_TOKEN=<YOUR_GITHUB_PAT_HERE>"
echo %GITHUB_TOKEN:~0,6%

# GTH — GitHub Threat Hunter

Standalone GitHub OSINT scanner for fast triage on GitHub users and organizations, with SOC-friendly JSON and HTML reports.

## Overview

GTH (GitHub Threat Hunter) is a lightweight standalone tool for OSINT-based technical analysis of GitHub users and organizations. It performs controlled repository sampling and pattern/heuristic-based secret detection using the official GitHub API.

Designed for:
- Security triage
- Blue-team investigations
- Open-source hygiene checks
- Exposure reconnaissance
- Technical due diligence

GTH is intentionally simple, fast, and field-ready.

## Features

- Target lookup (User / Organization)
- Controlled repository scanning (`--max-repos`, `--max-files`, `--max-depth`)
- Commit email extraction
- Secret detection (pattern/heuristic-based):
  - GitHub token patterns
  - AWS Access Key IDs
  - Slack tokens
  - Stripe secrets
  - Keyword-based secrets
  - Optional entropy detection
- Adjustable noise control (strict / balanced)
- JSON structured report output
- HTML visual report generation

## Requirements

- Python 3.9+
- GitHub Personal Access Token (PAT)

## Installation

Clone the repository and install dependencies:

git clone https://github.com/Neurone4444/gth-github-threat-hunter.git
cd gth-github-threat-hunter
pip install -r requirements.txt

If you don’t have requirements.txt, install manually:

pip install requests rich jinja2

## Quick Start

### Windows (CMD)

set "GITHUB_TOKEN=PASTE_YOUR_GITHUB_PAT_HERE"
python gth.py psf --token "%GITHUB_TOKEN%" --max-repos 5 --max-files 120 --max-depth 5 --hide-tests --entropy-threshold 4.85 --no-open

### Linux / macOS / Termux

export GITHUB_TOKEN="PASTE_YOUR_GITHUB_PAT_HERE"
python3 gth.py psf --token "$GITHUB_TOKEN" --max-repos 5 --max-files 120 --max-depth 5 --hide-tests --entropy-threshold 4.85 --no-open

## Scan Profiles

Balanced mode (recommended):

python gth.py target --token "$GITHUB_TOKEN" --max-repos 10 --max-files 200 --max-depth 6 --hide-tests --entropy-threshold 4.85 --no-open

Strict / Low-noise SOC mode:

python gth.py hashicorp --token "$GITHUB_TOKEN" --max-repos 4 --max-files 80 --max-depth 4 --hide-tests --no-entropy --no-open

Deep scan (large organizations):

python gth.py shopify --token "$GITHUB_TOKEN" --max-repos 15 --max-files 300 --max-depth 8 --hide-tests --entropy-threshold 4.7 --no-open

## Output

GTH generates:
- JSON report: output/gth_<target>_<timestamp>.json
- HTML report: output/gth_<target>_<timestamp>.html

Reports include:
- Target metadata
- Repository sampling summary
- Extracted commit emails
- Findings with severity scoring
- Pattern classification

## Security Note

- Treat your GitHub PAT as a secret.
- Never share it in screenshots or public logs.
- GTH detects patterns only.
- A detected secret does NOT imply it is valid or active.
- All findings must be manually reviewed in context.

## Limitations

- Scanning is sampled and limited by `--max-repos`, `--max-files`, and `--max-depth`.
- "No findings" does not guarantee absence of exposure.
- Only public repositories are analyzed.
- Results depend on GitHub API rate limits and repository visibility.

## License

MIT License — see LICENSE file for details.

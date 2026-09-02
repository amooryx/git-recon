#!/usr/bin/env python3
"""
Git Recon — GitHub Intelligence Gatherer for Red Team Reconnaissance
Discovers exposed credentials, internal endpoints, and org structure via GitHub API.
Author: Omar Khalid (amooryx) | github.com/amooryx/git-recon
AUTHORIZED USE ONLY — for authorized red team engagements and bug bounty.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlencode

BASE_URL = "https://api.github.com"

# ─── Patterns that indicate secrets ──────────────────────────────────────────
SECRET_PATTERNS = [
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?([A-Z0-9/+]{20,40})", "AWS Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",                    "Password"),
    (r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",        "API Key"),
    (r"(?i)(secret|token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",                  "Secret/Token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                                "Private Key"),
    (r"(?i)(mongodb|postgres|mysql|redis)://[^\s'\"]+",                                 "DB Connection String"),
    (r"(?i)ghp_[A-Za-z0-9]{36}",                                                        "GitHub PAT"),
    (r"(?i)xox[baprs]-[0-9A-Za-z\-]+",                                                  "Slack Token"),
    (r"(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",            "JWT"),
]

# ─── GitHub API wrapper ────────────────────────────────────────────────────────
class GitHubAPI:
    def __init__(self, token: str | None = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.rate_remaining = 60

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        url = f"{BASE_URL}{path}"
        if params:
            url += "?" + urlencode(params)
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", 60))
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return {"error": e.code, "msg": e.reason}

    def search_code(self, query: str, page: int = 1) -> dict:
        time.sleep(3)  # Rate limit courtesy sleep
        return self._get("/search/code", {"q": query, "per_page": 30, "page": page})

    def get_org(self, org: str) -> dict:
        return self._get(f"/orgs/{org}")

    def get_org_repos(self, org: str) -> list:
        repos = []
        page  = 1
        while True:
            batch = self._get(f"/orgs/{org}/repos", {"per_page": 100, "page": page, "type": "all"})
            if not isinstance(batch, list) or not batch:
                break
            repos.extend(batch)
            page += 1
        return repos

    def get_org_members(self, org: str) -> list:
        members = []
        page    = 1
        while True:
            batch = self._get(f"/orgs/{org}/members", {"per_page": 100, "page": page})
            if not isinstance(batch, list) or not batch:
                break
            members.extend(batch)
            page += 1
        return members

    def get_commits(self, repo_full: str, limit: int = 30) -> list:
        return self._get(f"/repos/{repo_full}/commits", {"per_page": limit})

    def get_file_content(self, repo_full: str, path: str) -> str | None:
        result = self._get(f"/repos/{repo_full}/contents/{path}")
        if isinstance(result, dict) and result.get("encoding") == "base64":
            import base64
            return base64.b64decode(result["content"]).decode(errors="ignore")
        return None

# ─── Recon functions ──────────────────────────────────────────────────────────
def scan_for_secrets_in_text(text: str, context: str = "") -> list[dict]:
    findings = []
    for pattern, name in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            findings.append({
                "type":    name,
                "match":   m.group(0)[:120],
                "context": context,
            })
    return findings

def org_recon(api: GitHubAPI, org: str) -> dict:
    print(f"[*] Recon org: {org}")
    info    = api.get_org(org)
    repos   = api.get_org_repos(org)
    members = api.get_org_members(org)

    print(f"  [+] Org: {info.get('name', org)} | {info.get('description','')}")
    print(f"  [+] Public repos: {info.get('public_repos', 0)} | Members: {len(members)}")
    print(f"  [+] Website: {info.get('blog','')}")

    repo_names = [r["full_name"] for r in repos if isinstance(r, dict)]
    print(f"  [+] Fetched {len(repo_names)} repos")

    return {
        "org":     org,
        "info":    info,
        "repos":   repo_names,
        "members": [m.get("login") for m in members if isinstance(m, dict)],
    }

def search_secrets(api: GitHubAPI, query: str, max_pages: int = 3) -> list[dict]:
    print(f"[*] Searching GitHub code: {query}")
    all_findings = []
    for page in range(1, max_pages + 1):
        results = api.search_code(query)
        if "error" in results:
            print(f"  [!] Search error: {results}")
            break
        items = results.get("items", [])
        print(f"  [+] Page {page}: {len(items)} results")
        for item in items:
            repo     = item.get("repository", {}).get("full_name", "")
            filepath = item.get("path", "")
            url      = item.get("html_url", "")
            content  = api.get_file_content(repo, filepath)
            if content:
                findings = scan_for_secrets_in_text(content, f"{repo}/{filepath}")
                for f in findings:
                    f["url"] = url
                    all_findings.append(f)
                    print(f"    [!] POTENTIAL SECRET [{f['type']}] in {repo}/{filepath}")
        if not items:
            break
    return all_findings

# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Git Recon — GitHub Intelligence Gatherer (Authorized use only)",
    )
    parser.add_argument("--token", help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    subparsers = parser.add_subparsers(dest="cmd")

    org_p = subparsers.add_parser("org",    help="Org reconnaissance (repos, members)")
    org_p.add_argument("org")
    org_p.add_argument("--out", help="Output JSON file")

    search_p = subparsers.add_parser("search", help="Search GitHub code for secrets")
    search_p.add_argument("query",       help="GitHub code search query (e.g. 'org:acme password filename:.env')")
    search_p.add_argument("--pages",     type=int, default=3)
    search_p.add_argument("--out",       help="Output JSON file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    api = GitHubAPI(args.token)

    if args.cmd == "org":
        result = org_recon(api, args.org)
        if args.out:
            with open(args.out, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[*] Results → {args.out}")

    elif args.cmd == "search":
        findings = search_secrets(api, args.query, args.pages)
        print(f"\n[*] Total potential secrets found: {len(findings)}")
        if args.out:
            with open(args.out, "w") as f:
                json.dump(findings, f, indent=2)
            print(f"[*] Results → {args.out}")
        else:
            for f in findings[:10]:
                print(f"  [{f['type']}] {f.get('context','')}: {f['match'][:80]}")

if __name__ == "__main__":
    main()

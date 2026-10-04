<div align="center">
  <img src="./banner.svg" alt="git-recon" width="800">
</div>

# Git Recon

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **Local, read-only check for likely secret-bearing filenames committed to a Git repository.**

## Usage

```bash
# Inspect the current repository
python git_recon.py .

# Inspect another local repository and save findings as JSON
python git_recon.py C:\projects\my-repo --yes --output findings.json

# Run the tests
python -m unittest discover -s tests
```

The check reads the local Git index and reports tracked `.env`-style files and
likely private-key or keystore filenames. It does not read file contents, make
network requests, or inspect untracked files. Example/template environment
files are excluded. Findings are filename-based indicators and should be
reviewed before taking action.

## Disclaimer

This tool operates only on a local repository path supplied by the user. It
does not accept remote targets or require credentials.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)

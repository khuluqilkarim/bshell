

# bshell — Automated Reverse Shell Finder (Authorized Testing Only)

> A CLI utility that **tests parameter-injection endpoints** by swapping in reverse-shell payload templates (from a local YAML), tracking results, and helping you trigger a connection **only in legally authorized labs or engagements**.

⚠️ **Legal & Ethical Use Only**
This tool is intended **exclusively** for defensive security, red-team exercises, and penetration testing **with written permission**. Do **not** use it against systems you don’t own or aren’t explicitly authorized to test.

---

## Key Features

* **Template-driven payloads**: pulls shell templates per OS from `~/.bshell/default.yaml`.
* **History tracking**: saves prior results to `~/.bshell/history.yaml` and offers reuse.
---

## How It Works (High Level)

1. Validates target reachability (HTTP 200).
2. Ensures the target URL contains the placeholder `FUZZ`.
3. Loads OS-specific shell templates (e.g., linux) from `~/.bshell/default.yaml`.
4. Iterates payloads by replacing `{host}` / `{port}` and injecting into `FUZZ`.
5. Sends requests and records potential hits (see **Detection logic** note below).
6. Saves successful candidates to `history.yaml` for quick re-execution later.

> **Detection logic note:** current implementation treats **timeouts** as a potential indicator (`brute_force_url` returns the crafted URL only on `Timeout`). You may want to enhance this (see **Limitations & Roadmap**) to include latency thresholds, content heuristics, callbacks, or out-of-band checks.

---

## Requirements

Install:

```bash
pip install -r requirements.txt
```

---

## Installation (CLI)

Make the script directly executable:

```bash
git clone https://github.com/khuluqilkarim/bshell.git
chmod +x bshell.py
# optional: put it on PATH
cp bshell.py  /usr/local/bin/bshell
```

Or expose it via `console_scripts` if you package it (recommended for teams).

---

## Usage

**Syntax**

```bash
bshell -u <TARGET_URL_WITH_FUZZ> -r <HOST:PORT> [-os linux] [--timeout 5] [--delay-threshold 1200]
```

**Parameters (table in English as requested):**

| Flag                    | Required | Description                                                                                                  |
| ----------------------- | -------: | ------------------------------------------------------------------------------------------------------------ |
| `-u, --url`             |      Yes | Target URL **containing `FUZZ`** where payload will be injected (e.g., `http://127.0.0.1:8000/run?cmd=FUZZ`) |
| `-r, --remote-hostport` |      Yes | Reverse listener address as `host:port` (e.g., `10.10.10.10:4444`)                                           |
| `-os, --osname`         |       No | OS key in template (`linux`, `windows`, etc.). Default: `linux`                                              |
| `--timeout`             |       No | Per-request timeout (seconds). Default: `5`                                                                  |
| `--delay-threshold`     |       No | Latency threshold (ms) you consider “success”. Default: `1200` (see **Limitations**)                         |

**Example (lab only):**

```bash
# Example against a deliberately vulnerable local app
bshell -u "http://127.0.0.1:8000/run?cmd=FUZZ" -r 127.0.0.1:4444 -os linux
```

During a subsequent run against the same target, bshell will offer to reuse the last successful payloads from `history.yaml`.

---

* **Template hygiene**: keep dangerous payloads **out of the repo** and store them privately; use per-engagement templates with strict access controls.

---

## Security & Ethics

* Only test assets with **explicit written authorization**.
* Log scope, approvals, and keep artifacts (`history.yaml`) for audit.
* Treat found payloads as **sensitive**; do not share externally.
* Prefer isolated labs (DVWA, deliberately vulnerable apps) for development.

---

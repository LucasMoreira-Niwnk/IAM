#!/opt/casa-terra-iam/backend/.venv/bin/python
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import winrm


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / "backend" / ".env")


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        print(f"{name} nao configurado.", file=sys.stderr)
        raise SystemExit(2)
    return value


def main() -> int:
    endpoint = required_env("GOOGLE_WORKSPACE_WINRM_ENDPOINT")
    username = required_env("GOOGLE_WORKSPACE_WINRM_USERNAME")
    password = required_env("GOOGLE_WORKSPACE_WINRM_PASSWORD")
    task_name = os.getenv("GOOGLE_WORKSPACE_TASK_NAME", "Sync - GCDS").strip() or "Sync - GCDS"
    transport = os.getenv("GOOGLE_WORKSPACE_WINRM_TRANSPORT", "ntlm").strip() or "ntlm"

    session = winrm.Session(endpoint, auth=(username, password), transport=transport)
    result = session.run_cmd("schtasks", ["/Run", "/TN", task_name])

    stdout = result.std_out.decode("utf-8", errors="ignore").strip()
    stderr = result.std_err.decode("utf-8", errors="ignore").strip()
    if stdout:
        print(stdout)
    if stderr:
        print(stderr, file=sys.stderr)

    return int(result.status_code)


if __name__ == "__main__":
    raise SystemExit(main())

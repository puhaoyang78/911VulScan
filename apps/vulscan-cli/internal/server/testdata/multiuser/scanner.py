#!/usr/bin/env python3
"""Deterministic subprocess adapter for real HTTP/concurrency tests; no models."""
import datetime
import hashlib
import json
import os
import sys
import time
from pathlib import Path

args = sys.argv[1:]
if "scan" not in args:
    raise SystemExit("Unexpected subprocess: " + repr(args))
root = Path(os.environ["VULSCAN_TEST_ROOT"])
job_id = os.environ["VULSCAN_JOB_ID"]
out = Path(args[args.index("--output") + 1])
config = Path(os.environ["XDG_CONFIG_HOME"]) / "vulscan/config.json"
settings = json.loads(config.read_text())
key = settings["llm_providers"]["deepseek"]["api_key"]
trace = {"config": str(config), "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
         "inherited_anthropic": os.environ.get("ANTHROPIC_API_KEY"),
         "inherited_openai": os.environ.get("OPENAI_API_KEY"),
         "dotenv_disabled": os.environ.get("PYTHON_DOTENV_DISABLED"),
         "docker_config": os.environ.get("DOCKER_CONFIG"),
         "docker_owner": os.environ["VULSCAN_DOCKER_OWNER"],
         "args": args}
(root / (job_id + ".started.json")).write_text(json.dumps(trace))

def emit(seq, kind, **fields):
    event = {"version": 1, "job_id": job_id, "seq": seq, "type": kind,
             "time": datetime.datetime.now(datetime.UTC).isoformat(), **fields}
    print("@vulscan-event " + json.dumps(event), file=sys.stderr, flush=True)

emit(1, "discovery.started")
emit(2, "finding.upsert", stage="analyze", finding_id="finding-1",
     finding={"finding_id": "finding-1", "title": "并发隔离用例", "model_review": "retained"})
emit(2, "finding.upsert", stage="analyze", finding_id="finding-1",
     finding={"finding_id": "finding-1", "title": "并发隔离用例", "model_review": "retained"})
# A real barrier keeps both subprocesses alive until the HTTP test verifies them.
deadline = time.monotonic() + 25
while not (root / "release").exists():
    if time.monotonic() > deadline:
        raise SystemExit("Concurrent test barrier timed out")
    time.sleep(0.05)
(out / "report.html").write_text("<!doctype html><title>911VulScan</title><h1>并发扫描报告</h1>")
(out / "SUMMARY_REPORT.md").write_text("# 并发扫描摘要\n\n本账号的扫描结果。")
(out / "report/disclosures").mkdir(parents=True, exist_ok=True)
(out / "report/disclosures/DISCLOSURE_01.md").write_text("# 漏洞报告：隔离用例\n\n## 影响\n\n测试内容。")
print(json.dumps({"status": "success", "data": {}}))

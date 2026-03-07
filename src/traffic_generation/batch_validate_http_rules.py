from __future__ import annotations

import json
import re
import random
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from parsuricata import parse_rules
from parse.parsuricata_adapter import rule_to_suricata_rule

from traffic_generation.http_fixed import (
    send_http_request,
    send_raw_http_bytes,
    render_http_request,
    build_transaction_artifacts_for_rule,
)

# =========================
# 配置区：按你的环境修改
# =========================
DATASET_PATH = Path(r"E:\Develop\devpy\experiment\resources\dataset\converted_emerging-all_http.rules")

TARGET_SERVER = "http://192.168.1.199:80"
TARGET_HOST = "192.168.1.199"
TARGET_PORT = 80

# Wireshark / Npcap 的 dumpcap
DUMPCAP_EXE = Path(r"E:\Wireshark\dumpcap.exe")

# Suricata
SURICATA_EXE = Path(r"C:\Program Files\Suricata\suricata.exe")
SURICATA_YAML = Path(r"C:\Program Files\Suricata\suricata.yaml")

# 抓包网卡
CAPTURE_INTERFACE = r"\Device\NPF_{A4219C22-46C9-47A5-A0BD-50DC4B06644A}"  # VMnet1

# 输出目录
OUTPUT_ROOT = Path(r"E:\Develop\devpy\experiment\resources\validation_run")
SUCCESS_ROOT = OUTPUT_ROOT / "success"
FAILED_ROOT = OUTPUT_ROOT / "failed"
TEMP_ROOT = OUTPUT_ROOT / "temp"
FAILED_SIDS_FILE = OUTPUT_ROOT / "failed_sids.txt"
RUN_LOG = OUTPUT_ROOT / "run_log.jsonl"
CAPINFOS_EXE = Path(r"E:\Wireshark\capinfos.exe")

# 先跑前 10 条
MAX_RULES = 10

# 每条规则请求后等待抓包刷盘的时间
CAPTURE_SETTLE_SECONDS = 1.0
REQUEST_TIMEOUT = 3

# 进度统计
SUCCESS_COUNT = 0
FAIL_COUNT = 0


def console(msg: str) -> None:
    now = time.strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def ensure_dirs() -> None:
    for p in [OUTPUT_ROOT, SUCCESS_ROOT, FAILED_ROOT, TEMP_ROOT]:
        p.mkdir(parents=True, exist_ok=True)


def log_json(obj: dict) -> None:
    with RUN_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def append_failed_sid(sid: str, reason: str) -> None:
    with FAILED_SIDS_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{sid}\t{reason}\n")


def safe_sid(raw_sid: str) -> str:
    sid = (raw_sid or "").strip()
    return sid if sid else "NO_SID"


def rough_extract_sid(rule_text: str) -> str:
    m = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule_text, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    return "NO_SID"


def extract_rule_feature_summary(rule) -> dict:
    clauses = list(getattr(rule.body, "clauses", []) or [])
    by_type = {
        "content": 0,
        "pcre": 0,
        "buffer_switch": 0,
        "negated_content": 0,
        "with_distance_or_within": 0,
        "with_offset_or_depth": 0,
    }
    buffers = set()
    for c in clauses:
        name = c.__class__.__name__
        if name == "ContentMatch":
            by_type["content"] += 1
            if getattr(c, "negated", False):
                by_type["negated_content"] += 1
            if getattr(c, "distance", None) is not None or getattr(c, "within", None) is not None:
                by_type["with_distance_or_within"] += 1
            if getattr(c, "offset", None) is not None or getattr(c, "depth", None) is not None:
                by_type["with_offset_or_depth"] += 1
            if getattr(c, "buffer", None):
                buffers.add(getattr(c, "buffer"))
        elif name == "PcreMatch":
            by_type["pcre"] += 1
            if getattr(c, "buffer", None):
                buffers.add(getattr(c, "buffer"))
        elif name == "BufferSwitch":
            by_type["buffer_switch"] += 1
            buffers.add(getattr(c, "buffer", ""))

    flow = getattr(rule.body, "flow", None)
    return {
        "sid": getattr(rule.body, "sid", ""),
        "flow": {
            "to_server": bool(getattr(flow, "to_server", False)) if flow else False,
            "to_client": bool(getattr(flow, "to_client", False)) if flow else False,
            "established": bool(getattr(flow, "established", False)) if flow else False,
        },
        "counts": by_type,
        "buffers": sorted(b for b in buffers if b),
    }


def build_request_from_rule_text(rule_text: str):
    rules = parse_rules(rule_text)
    if not rules:
        raise ValueError("parse_rules returned empty")

    rule_original = rules[0]
    rule = rule_to_suricata_rule(rule_original)
    sid = safe_sid(rule.body.sid)

    strategy, req, raw_bytes, synthetic_resp = build_transaction_artifacts_for_rule(rule, TARGET_SERVER)

    console(f"[{sid}] strategy={strategy}")
    console(f"[{sid}] clause_count={len(rule.body.clauses)}")
    for c in rule.body.clauses[:10]:
        console(f"  clause: {c}")

    if req is not None:
        console(f"[{sid}] structured/recoverable request built")
        console(render_http_request(req))
    else:
        console(f"[{sid}] raw text request built")
        if raw_bytes is None:
            raise ValueError(f"{sid}: strategy=raw_text but raw_bytes is None")
        console(raw_bytes.decode("latin-1", errors="replace"))

    return rule, strategy, req, raw_bytes, synthetic_resp


def start_capture(pcap_path: Path) -> subprocess.Popen:
    cmd = [
        str(DUMPCAP_EXE),
        "-i", CAPTURE_INTERFACE,
        "-w", str(pcap_path),
    ]

    console(f"starting dumpcap: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(1.0)

    if proc.poll() is not None:
        stdout, stderr = proc.communicate(timeout=2)
        raise RuntimeError(
            f"dumpcap exited immediately, returncode={proc.returncode}, "
            f"stdout={stdout!r}, stderr={stderr!r}"
        )

    time.sleep(CAPTURE_SETTLE_SECONDS)
    return proc


def show_pcap_summary(pcap_path: Path) -> None:
    if not pcap_path.exists():
        return
    console(f"pcap file size={pcap_path.stat().st_size} bytes")
    if CAPINFOS_EXE.exists():
        try:
            proc = subprocess.run(
                [str(CAPINFOS_EXE), str(pcap_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if "Number of packets" in line or "File size" in line:
                        console(line.strip())
        except Exception as e:
            console(f"capinfos failed: {e!r}")


def stop_capture(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=5)
        if stdout:
            console(f"dumpcap stdout: {stdout.strip()}")
        if stderr:
            console(f"dumpcap stderr: {stderr.strip()}")
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    time.sleep(0.5)


def run_suricata_verify(pcap_path: Path, rule_path: Path, out_dir: Path) -> bool:
    """
    用 Suricata 离线回放 pcap，只加载该条规则。
    """
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(SURICATA_EXE),
        "-c", str(SURICATA_YAML),
        "-S", str(rule_path),
        "-r", str(pcap_path),
        "-l", str(out_dir),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        log_json({
            "stage": "suricata_run",
            "pcap": str(pcap_path),
            "rule": str(rule_path),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        })
        return False

    eve_path = out_dir / "eve.json"
    fast_path = out_dir / "fast.log"

    if eve_path.exists():
        try:
            with eve_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if obj.get("event_type") == "alert":
                        return True
        except Exception:
            pass

    if fast_path.exists():
        try:
            txt = fast_path.read_text(encoding="utf-8", errors="ignore").strip()
            if txt:
                return True
        except Exception:
            pass

    return False


def save_success_artifacts(sid: str, rule_text: str, pcap_path: Path) -> None:
    sid_dir = SUCCESS_ROOT / sid
    sid_dir.mkdir(parents=True, exist_ok=True)

    dst_pcap = sid_dir / f"{sid}.pcap"
    dst_rule = sid_dir / f"{sid}.rules"

    shutil.copy2(pcap_path, dst_pcap)
    dst_rule.write_text(rule_text.strip() + "\n", encoding="utf-8")


def save_failed_artifacts(sid: str, rule_text: str, pcap_path: Optional[Path], reason: str) -> None:
    sid_dir = FAILED_ROOT / sid
    sid_dir.mkdir(parents=True, exist_ok=True)

    dst_rule = sid_dir / f"{sid}.rules"
    dst_rule.write_text(rule_text.strip() + "\n", encoding="utf-8")

    if pcap_path is not None and pcap_path.exists():
        shutil.copy2(pcap_path, sid_dir / f"{sid}.pcap")

    append_failed_sid(sid, reason)


def process_one_rule(rule_text: str, index: int, total: int) -> None:
    global SUCCESS_COUNT, FAIL_COUNT

    if not rule_text.strip():
        return

    pcap_path: Optional[Path] = None
    capture_proc: Optional[subprocess.Popen] = None
    t0 = time.time()

    sid = rough_extract_sid(rule_text)

    try:
        console(f"[{index}/{total}] sid={sid} parsing/building request...")
        rule, strategy, req, raw_bytes, synthetic_resp = build_request_from_rule_text(rule_text)
        rule_features = extract_rule_feature_summary(rule)
        sid = safe_sid(rule.body.sid)

        console(f"[{index}/{total}] sid={sid} rule_features={rule_features}")

        if req is not None:
            console(f"[{index}/{total}] sid={sid} built request detail:")
            console(f"  strategy={strategy}")
            console(f"  method={req.method}")
            console(f"  path={req.path}")
            console(f"  headers={req.headers}")
            console(f"  body={req.body[:200]!r}")
            console(f"[{index}/{total}] sid={sid} request built: {req.method} {req.path}")
        else:
            if raw_bytes is None:
                raise ValueError(f"{sid}: raw_bytes is None")
            preview = raw_bytes.decode("latin-1", errors="replace")
            console(f"[{index}/{total}] sid={sid} built raw-text request detail:")
            console(f"  strategy={strategy}")
            console(preview[:500])

        temp_rule_path = TEMP_ROOT / f"{sid}.rules"
        temp_pcap_path = TEMP_ROOT / f"{sid}.pcap"
        suri_out_dir = TEMP_ROOT / f"suricata_{sid}"

        temp_rule_path.write_text(rule_text.strip() + "\n", encoding="utf-8")
        pcap_path = temp_pcap_path

        console(f"[{index}/{total}] sid={sid} starting capture...")
        capture_proc = start_capture(temp_pcap_path)

        console(f"[{index}/{total}] sid={sid} sending request...")
        console(f"[{index}/{total}] sid={sid} rule_features={rule_features}")

        if req is not None:
            status, _ = send_http_request(TARGET_SERVER, req, timeout=REQUEST_TIMEOUT)
        else:
            if raw_bytes is None:
                raise ValueError(f"{sid}: raw_bytes is None before send")
            status, _ = send_raw_http_bytes(TARGET_SERVER, raw_bytes, timeout=REQUEST_TIMEOUT)
        time.sleep(2)

        console(f"[{index}/{total}] sid={sid} stopping capture...")
        stop_capture(capture_proc)
        show_pcap_summary(temp_pcap_path)
        if temp_pcap_path.exists():
            console(f"[{index}/{total}] sid={sid} pcap size={temp_pcap_path.stat().st_size} bytes")
        capture_proc = None

        console(f"[{index}/{total}] sid={sid} running suricata verify...")
        hit = run_suricata_verify(temp_pcap_path, temp_rule_path, suri_out_dir)

        elapsed = round(time.time() - t0, 2)

        log_json({
            "index": index,
            "total": total,
            "sid": sid,
            "strategy": strategy,
            "status": status,
            "hit": hit,
            "elapsed_sec": elapsed,
            "path": (req.path if req is not None else None),
            "headers": (req.headers if req is not None else None),
            "body": (req.body if req is not None else None),
            "raw_text": (
                raw_bytes.decode("latin-1", errors="replace")
                if raw_bytes is not None else None
            ),
            "synthetic_response_preview": (
                synthetic_resp.decode("latin-1", errors="replace")[:400]
                if synthetic_resp is not None else None
            ),
            "rule_features": rule_features,
        })

        if hit:
            SUCCESS_COUNT += 1
            console(f"[{index}/{total}] sid={sid} ✅ alert hit  status={status}  elapsed={elapsed}s")
            save_success_artifacts(sid, rule_text, temp_pcap_path)
        else:
            FAIL_COUNT += 1
            console(f"[{index}/{total}] sid={sid} ❌ no alert  status={status}  elapsed={elapsed}s")
            save_failed_artifacts(sid, rule_text, temp_pcap_path, "no_alert")

    except Exception as e:
        FAIL_COUNT += 1

        if capture_proc is not None:
            stop_capture(capture_proc)

        elapsed = round(time.time() - t0, 2)

        console(f"[{index}/{total}] sid={sid} 💥 exception after {elapsed}s: {repr(e)}")

        log_json({
            "index": index,
            "total": total,
            "sid": sid,
            "elapsed_sec": elapsed,
            "error": repr(e),
            "rule": rule_text,
        })
        save_failed_artifacts(sid, rule_text, pcap_path, f"exception: {repr(e)}")


# def main() -> None:
#     ensure_dirs()
#
#     if not DATASET_PATH.exists():
#         raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")
#     if not DUMPCAP_EXE.exists():
#         raise FileNotFoundError(f"dumpcap not found: {DUMPCAP_EXE}")
#     if not SURICATA_EXE.exists():
#         raise FileNotFoundError(f"suricata not found: {SURICATA_EXE}")
#     if not SURICATA_YAML.exists():
#         raise FileNotFoundError(f"suricata yaml not found: {SURICATA_YAML}")
#
#     lines = DATASET_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
#
#     selected_rules = []
#     for line in lines:
#         rule_text = line.strip()
#         if rule_text:
#             selected_rules.append(rule_text)
#         if len(selected_rules) >= MAX_RULES:
#             break
#
#     total = len(selected_rules)
#     console(f"Starting batch validation. total={total}")
#
#     count = 0
#     for idx, rule_text in enumerate(selected_rules, start=1):
#         console("=" * 80)
#         process_one_rule(rule_text, idx, total)
#         count += 1
#
#         if idx % 10 == 0:
#             console(f"Progress: {idx}/{total}  success={SUCCESS_COUNT}  failed={FAIL_COUNT}")
#
#     console("=" * 80)
#     console(f"Done. processed={count}/{total}  success={SUCCESS_COUNT}  failed={FAIL_COUNT}")

def main() -> None:
    random.seed()  # 如果想固定结果，改成 random.seed(42)
    ensure_dirs()

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")
    if not DUMPCAP_EXE.exists():
        raise FileNotFoundError(f"dumpcap not found: {DUMPCAP_EXE}")
    if not SURICATA_EXE.exists():
        raise FileNotFoundError(f"suricata not found: {SURICATA_EXE}")
    if not SURICATA_YAML.exists():
        raise FileNotFoundError(f"suricata yaml not found: {SURICATA_YAML}")

    lines = DATASET_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()

    indexed_rules = []
    for line_no, line in enumerate(lines, start=1):
        rule_text = line.strip()
        if rule_text:
            indexed_rules.append((line_no, rule_text))

    if not indexed_rules:
        raise ValueError("No valid rules found in dataset")

    sample_size = min(MAX_RULES, len(indexed_rules))
    selected_rules = random.sample(indexed_rules, sample_size)

    total = len(selected_rules)
    console(f"Starting batch validation. total={total}")

    count = 0
    for idx, (line_no, rule_text) in enumerate(selected_rules, start=1):
        console("=" * 80)
        console(f"[{idx}/{total}] source line={line_no}")
        process_one_rule(rule_text, idx, total)
        count += 1

        if idx % 10 == 0:
            console(f"Progress: {idx}/{total}  success={SUCCESS_COUNT}  failed={FAIL_COUNT}")

    console("=" * 80)
    console(f"Done. processed={count}/{total}  success={SUCCESS_COUNT}  failed={FAIL_COUNT}")

if __name__ == "__main__":
    main()
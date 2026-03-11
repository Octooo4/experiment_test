from __future__ import annotations

import argparse
import json
import re
import random
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from parse.buckets_sorting import clauses_to_terms, split_clauses_for_http_generation
from traffic_generation.buffer_solver import synthesize_bucket
from traffic_generation.http_builder import (
    build_http_request_from_raw_clauses,
    build_http_request_from_buckets,
    build_raw_http_text_request_from_clauses,
    build_request,
    build_request_for_rule,
    ensure_common_headers,
    render_http_request,
)
from traffic_generation.traffic_emit import send_raw_http_bytes
from traffic_generation.validate.batch_validate_rules import choose_rule_adapter, emit_rule_payload
from traffic_generation.rule_parse import Rule, ast_to_suricata_rule, parse_rules
from traffic_generation.rule_semantics import classify_http_rule_strategy, extract_http_plan, get_rule_admission_skip_reason

SKIP_NOT_ALERT_HTTP = "SKIP_NOT_ALERT_HTTP"
SKIP_OUT_OF_SCOPE_TO_SERVER_ONLY = "SKIP_OUT_OF_SCOPE_TO_SERVER_ONLY"
SKIP_UNSUPPORTED_KEYWORD = "SKIP_UNSUPPORTED_KEYWORD"
UNSUPPORTED_KEYWORD = "UNSUPPORTED_KEYWORD"
UNSUPPORTED_PCRE = "UNSUPPORTED_PCRE"
CONSTRAINT_UNSAT = "CONSTRAINT_UNSAT"
BUILD_REQUEST_FAILED = "BUILD_REQUEST_FAILED"
EMIT_FAILED = "EMIT_FAILED"
SURICATA_FAILED = "SURICATA_FAILED"
NO_ALERT_FOR_SID = "NO_ALERT_FOR_SID"
FLOW_NOT_ESTABLISHED = "FLOW_NOT_ESTABLISHED"
HTTP_PARSE_SUSPECT = "HTTP_PARSE_SUSPECT"
BUFFER_MAPPING_SUSPECT = "BUFFER_MAPPING_SUSPECT"
UNSUPPORTED_BINARY_HTTP_FIELD = "UNSUPPORTED_BINARY_HTTP_FIELD"


@dataclass
class ValidationResult:
    sid: str
    msg: str
    status: str
    skip_reason: Optional[str] = None
    miss_reason: Optional[str] = None
    request_path: Optional[str] = None
    pcap_path: Optional[str] = None
    eve_path: Optional[str] = None
    unsupported_features: list[str] = field(default_factory=list)
    solver_backend: Optional[str] = None
    traffic_type: Optional[str] = None
    generation_success: bool = False


@dataclass
class ValidationConfig:
    dataset_path: Path
    target_server: str
    output_root: Path
    dumpcap_exe: Path
    capture_interface: str
    suricata_exe: Path
    suricata_yaml: Path
    capinfos_exe: Optional[Path]
    max_rules: int
    request_timeout: float
    capture_settle_seconds: float
    post_request_sleep_seconds: float


def console(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def safe_sid(raw_sid: str) -> str:
    sid = (raw_sid or "").strip()
    return sid if sid else "NO_SID"


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch validate HTTP rules via pipeline")
    parser.add_argument("--dataset", required=False, help="Path to rules dataset")
    parser.add_argument("--target-server", required=False, help="HTTP target, e.g. http://127.0.0.1:8080")
    parser.add_argument("--output-root", required=False, help="Output root directory")
    parser.add_argument("--dumpcap-exe", required=False, help="dumpcap executable path")
    parser.add_argument("--capture-interface", required=False, help="dumpcap interface name")
    parser.add_argument("--suricata-exe", required=False, help="suricata executable path")
    parser.add_argument("--suricata-yaml", required=False, help="suricata.yaml path")
    parser.add_argument("--capinfos-exe", default=None, help="capinfos executable path")
    parser.add_argument("--max-rules", type=int, default=10)
    parser.add_argument("--request-timeout", type=float, default=3.0)
    parser.add_argument("--capture-settle-seconds", type=float, default=1.0)
    parser.add_argument("--post-request-sleep-seconds", type=float, default=2.0)
    parser.add_argument("--config", default=None, help="Optional JSON config file. CLI args override it")
    return parser.parse_args()


def load_config() -> ValidationConfig:
    args = parse_args()
    file_cfg: dict[str, Any] = {}
    if args.config:
        file_cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))

    def pick(name: str, default: Any = None) -> Any:
        val = getattr(args, name)
        if val is not None:
            return val
        return file_cfg.get(name, default)

    def need(name: str) -> Any:
        val = pick(name)
        if val is None:
            raise ValueError(f"Missing required config value: {name}")
        return val

    return ValidationConfig(
        dataset_path=Path(need("dataset")),
        target_server=need("target_server"),
        output_root=Path(need("output_root")),
        dumpcap_exe=Path(need("dumpcap_exe")),
        capture_interface=need("capture_interface"),
        suricata_exe=Path(need("suricata_exe")),
        suricata_yaml=Path(need("suricata_yaml")),
        capinfos_exe=Path(pick("capinfos_exe")) if pick("capinfos_exe") else None,
        max_rules=int(pick("max_rules", 10)),
        request_timeout=float(pick("request_timeout", 3.0)),
        capture_settle_seconds=float(pick("capture_settle_seconds", 1.0)),
        post_request_sleep_seconds=float(pick("post_request_sleep_seconds", 2.0)),
    )


def validate_inputs(cfg: ValidationConfig) -> None:
    required_paths = [
        (cfg.dataset_path, "dataset"),
        (cfg.dumpcap_exe, "dumpcap"),
        (cfg.suricata_exe, "suricata"),
        (cfg.suricata_yaml, "suricata yaml"),
    ]
    for path, name in required_paths:
        if not path.exists():
            raise FileNotFoundError(f"{name} not found: {path}")


def start_capture(cfg: ValidationConfig, pcap_path: Path) -> subprocess.Popen:
    cmd = [str(cfg.dumpcap_exe), "-i", cfg.capture_interface, "-w", str(pcap_path)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(cfg.capture_settle_seconds)
    if proc.poll() is not None:
        stdout, stderr = proc.communicate(timeout=2)
        raise RuntimeError(f"dumpcap exited early rc={proc.returncode} stdout={stdout!r} stderr={stderr!r}")
    return proc


def stop_capture(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.communicate(timeout=5)
    except Exception:
        proc.kill()


def run_suricata_verify(cfg: ValidationConfig, pcap_path: Path, rule_path: Path, out_dir: Path) -> tuple[bool, Path]:
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(cfg.suricata_exe),
        "-c",
        str(cfg.suricata_yaml),
        "-S",
        str(rule_path),
        "-r",
        str(pcap_path),
        "-l",
        str(out_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"suricata rc={proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}")

    eve_path = out_dir / "eve.json"
    if eve_path.exists():
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
                    return True, eve_path
    return False, eve_path


def build_rule_plan(rule, rule_ast: Rule) -> dict[str, Any]:
    buckets = split_clauses_for_http_generation(rule.body.clauses)
    bucket_terms = {
        k: clauses_to_terms(v)
        for k, v in buckets.items()
        if isinstance(v, list) and k != "other"
    }
    solver_backends: dict[str, str] = {}
    unsat_reasons: dict[str, str] = {}
    unsupported_pcre: list[str] = []

    for bucket_name, clauses in buckets.items():
        if not isinstance(clauses, list) or not clauses:
            continue
        try:
            synth = synthesize_bucket(clauses, sid=rule.body.sid)
        except Exception as e:
            msg = str(e)
            if "pcre" in msg.lower() or "regex" in msg.lower() or "exrex" in msg.lower():
                unsupported_pcre.append(f"{bucket_name}:{msg}")
            else:
                unsat_reasons[bucket_name] = msg
        else:
            solver_backends[bucket_name] = synth.solved_by
            if synth.solved_by == "greedy" and synth.unsat_reason:
                unsat_reasons[bucket_name] = synth.unsat_reason

    tx_plan = extract_http_plan(rule)
    tx_plan_dict = {
        "flow": {
            "to_server": tx_plan.flow.to_server,
            "established": tx_plan.flow.established,
            "not_established": tx_plan.flow.not_established,
        },
        "request_segments": [
            {
                "buffer": seg.buffer,
                "matches": [
                    {
                        "kind": m.kind,
                        "raw": m.raw,
                        "modifiers": {
                            "nocase": m.modifiers.nocase,
                            "startswith": m.modifiers.startswith,
                            "endswith": m.modifiers.endswith,
                            "offset": m.modifiers.offset,
                            "depth": m.modifiers.depth,
                            "distance": m.modifiers.distance,
                            "within": m.modifiers.within,
                            "rawbytes": m.modifiers.rawbytes,
                            "negated": m.modifiers.negated,
                        },
                    }
                    for m in seg.matches
                ],
            }
            for seg in tx_plan.request_segments
        ],
    }

    return {
        "sid": rule.body.sid,
        "msg": rule.body.msg,
        "flow": rule.body.flow.model_dump() if rule.body.flow else None,
        "transaction_plan": tx_plan_dict,
        "unsupported_keywords": sorted(set(rule_ast.unsupported_keywords)),
        "mapping_suspect": bool(buckets.get("_mapping_suspect")),
        "bucket_terms": bucket_terms,
        "solver_backends": solver_backends,
        "unsupported_pcre": unsupported_pcre,
        "unsat_reasons": unsat_reasons,
    }


def normalize_rule_for_suricata_eval(rule_text: str) -> str:
    """
    归一化 rule header，避免对 HOME_NET/EXTERNAL_NET/HTTP_PORTS 变量配置强依赖。
    仅用于离线回放验证，不改动 options。
    """
    text = (rule_text or "").strip()
    m = re.match(r"^\s*(alert|pass|drop|reject|log)\s+(\S+)\s+\S+\s+\S+\s+(->|<>)\s+\S+\s+\S+\s*\(", text, flags=re.IGNORECASE)
    if not m:
        return text
    action = m.group(1)
    protocol = m.group(2)
    direction = m.group(3)
    normalized = f"{action} {protocol} any any {direction} any any ("
    return normalized + text[m.end():]


def initialize_artifacts_dir(root: Path, sid: str, index: int) -> Path:
    sid_dir = root / f"{sid}_{index:05d}"
    sid_dir.mkdir(parents=True, exist_ok=True)
    (sid_dir / "request.bin").write_bytes(b"")
    (sid_dir / "traffic.pcap").write_bytes(b"")
    (sid_dir / "eve.json").write_text("", encoding="utf-8")
    return sid_dir


def should_try_legacy_fallback(strategy: str) -> bool:
    return strategy in {"sticky", "recoverable_raw", "raw_text"}


def should_short_circuit_unsat(adapter: str, unsat_reasons: list[str]) -> bool:
    return adapter == "http" and bool(unsat_reasons)


def _render_fallback_bytes(req_obj, raw_bytes: Optional[bytes]) -> bytes:
    if req_obj is not None:
        return render_http_request(req_obj).encode("latin-1", errors="replace")
    return raw_bytes or b""


def build_fallback_attempts(rule, target_server: str) -> list[tuple[str, bytes]]:
    """
    Build fallback request candidates in descending preference.
    Plan path stays primary; these only run after a miss or unsat.
    """
    attempts: list[tuple[str, bytes]] = []

    def add_attempt(name: str, payload: bytes) -> None:
        if not payload:
            return
        for n, p in attempts:
            if n == name and p == payload:
                return
        if any(p == payload for _, p in attempts):
            return
        attempts.append((name, payload))

    try:
        buckets = split_clauses_for_http_generation(rule.body.clauses)
        if not buckets.get("_mapping_suspect"):
            req_bucket = build_http_request_from_buckets(buckets, sid=rule.body.sid)
            ensure_common_headers(target_server, req_bucket)
            add_attempt("sticky_bucket", render_http_request(req_bucket).encode("latin-1", errors="replace"))
    except Exception:
        pass

    strategy, req_obj, raw_bytes = build_request_for_rule(rule, target_server)
    add_attempt(strategy, _render_fallback_bytes(req_obj, raw_bytes))

    try:
        raw_req = build_http_request_from_raw_clauses(rule.body.clauses, sid=rule.body.sid)
        ensure_common_headers(target_server, raw_req)
        add_attempt("recoverable_raw", render_http_request(raw_req).encode("latin-1", errors="replace"))
    except Exception:
        pass
    try:
        raw_text = build_raw_http_text_request_from_clauses(rule.body.clauses, sid=rule.body.sid)
        add_attempt("raw_text", raw_text)
    except Exception:
        pass

    return attempts


def run_fallback_attempts(
    cfg: ValidationConfig,
    rule,
    request_bytes: bytes,
    req_path: Path,
    pcap_path: Path,
    rule_path: Path,
    status_code: Optional[int],
) -> tuple[bool, Path, Optional[int], str]:
    """Run fallback attempts and return (hit, eve_path, status_code, solver_backend)."""
    hit, produced_eve_path = run_suricata_verify(cfg, pcap_path, rule_path, pcap_path.parent / "suricata_out")
    solver_backend = "plan"
    if hit:
        return hit, produced_eve_path, status_code, solver_backend

    for fallback_strategy, fb_bytes in build_fallback_attempts(rule, cfg.target_server):
        if not fb_bytes or fb_bytes == request_bytes:
            continue
        req_path.write_bytes(fb_bytes)
        solver_backend = f"plan_fallback_{fallback_strategy}"
        capture_proc = start_capture(cfg, pcap_path)
        try:
            status_code, _ = send_raw_http_bytes(cfg.target_server, fb_bytes, timeout=cfg.request_timeout)
            time.sleep(cfg.post_request_sleep_seconds)
        finally:
            stop_capture(capture_proc)
        hit, produced_eve_path = run_suricata_verify(cfg, pcap_path, rule_path, pcap_path.parent / "suricata_out")
        if hit:
            break
    return hit, produced_eve_path, status_code, solver_backend


def log_rule_result(index: int, total: int, result: ValidationResult) -> None:
    console(
        f"[{index}/{total}] sid={result.sid} "
        f"traffic_type={result.traffic_type or 'unknown'} "
        f"generation_success={result.generation_success} "
        f"status={result.status}"
    )


def process_one_rule(cfg: ValidationConfig, rule_ast: Rule, index: int, total: int) -> ValidationResult:
    sid = safe_sid(rule_ast.sid)
    msg = rule_ast.msg or ""
    console(f"[{index}/{total}] sid={sid} pipeline start")

    rule = ast_to_suricata_rule(rule_ast)
    sid = safe_sid(rule.body.sid)
    msg = rule.body.msg or msg

    sid_dir = initialize_artifacts_dir(cfg.output_root, sid, index)
    rule_path = sid_dir / "rule.txt"
    plan_path = sid_dir / "plan.json"
    req_path = sid_dir / "request.bin"
    pcap_path = sid_dir / "traffic.pcap"
    eve_path = sid_dir / "eve.json"
    diagnose_path = sid_dir / "diagnose.json"

    normalized_rule_text = normalize_rule_for_suricata_eval(rule_ast.raw_text)
    rule_path.write_text(normalized_rule_text.strip() + "\n", encoding="utf-8")

    plan = build_rule_plan(rule, rule_ast)
    adapter = choose_rule_adapter(rule)
    traffic_type = "http" if adapter == "http" else ("dns" if adapter == "dns" else ("udp" if adapter == "udp_raw" else "tcp"))
    console(f"[{index}/{total}] sid={sid} traffic_type={traffic_type}")

    write_json(plan_path, plan)

    unsupported_features: list[str] = []
    if plan["unsupported_keywords"]:
        unsupported_features.extend([f"keyword:{x}" for x in plan["unsupported_keywords"]])

    skip_reason = get_rule_admission_skip_reason(rule) if adapter == "http" else None
    if skip_reason:
        result = ValidationResult(
            sid=sid,
            msg=msg,
            status="SKIPPED",
            skip_reason=skip_reason,
            request_path=str(req_path),
            pcap_path=str(pcap_path),
            eve_path=str(eve_path),
            unsupported_features=unsupported_features,
            traffic_type=traffic_type,
            generation_success=False,
        )
        write_json(diagnose_path, {"stage": "filter", "reason": skip_reason, "result": asdict(result)})
        return result

    if plan["unsupported_keywords"]:
        result = ValidationResult(
            sid=sid,
            msg=msg,
            status="SKIPPED",
            skip_reason=SKIP_UNSUPPORTED_KEYWORD,
            request_path=str(req_path),
            pcap_path=str(pcap_path),
            eve_path=str(eve_path),
            unsupported_features=unsupported_features,
            traffic_type=traffic_type,
            generation_success=False,
        )
        write_json(diagnose_path, {"stage": "extract_plan", "reason": SKIP_UNSUPPORTED_KEYWORD, "result": asdict(result)})
        return result

    if plan["unsupported_pcre"]:
        result = ValidationResult(
            sid=sid,
            msg=msg,
            status="MISS",
            miss_reason=UNSUPPORTED_PCRE,
            request_path=str(req_path),
            pcap_path=str(pcap_path),
            eve_path=str(eve_path),
            unsupported_features=unsupported_features + plan["unsupported_pcre"],
            traffic_type=traffic_type,
            generation_success=False,
        )
        write_json(diagnose_path, {"stage": "solve", "reason": UNSUPPORTED_PCRE, "result": asdict(result)})
        return result

    if should_short_circuit_unsat(adapter, plan["unsat_reasons"]):
        capture_proc: Optional[subprocess.Popen] = None
        try:
            status_code = None
            hit = False
            produced_eve_path = eve_path
            solver_backend = None
            generation_success = False

            for fallback_strategy, fb_bytes in build_fallback_attempts(rule, cfg.target_server):
                if not fb_bytes:
                    continue
                req_path.write_bytes(fb_bytes)
                solver_backend = f"fallback_{fallback_strategy}_after_unsat"
                capture_proc = start_capture(cfg, pcap_path)
                try:
                    status_code, _ = send_raw_http_bytes(cfg.target_server, fb_bytes, timeout=cfg.request_timeout)
                    generation_success = True
                    time.sleep(cfg.post_request_sleep_seconds)
                finally:
                    stop_capture(capture_proc)
                    capture_proc = None
                hit, produced_eve_path = run_suricata_verify(cfg, pcap_path, rule_path, sid_dir / "suricata_out")
                if hit:
                    break

            if produced_eve_path.exists():
                shutil.copy2(produced_eve_path, eve_path)

            if hit:
                result = ValidationResult(
                    sid=sid,
                    msg=msg,
                    status="PASS",
                    request_path=str(req_path),
                    pcap_path=str(pcap_path),
                    eve_path=str(eve_path),
                    unsupported_features=unsupported_features,
                    solver_backend=solver_backend,
                    traffic_type=traffic_type,
                    generation_success=generation_success,
                )
            else:
                result = ValidationResult(
                    sid=sid,
                    msg=msg,
                    status="MISS",
                    miss_reason=CONSTRAINT_UNSAT,
                    request_path=str(req_path),
                    pcap_path=str(pcap_path),
                    eve_path=str(eve_path),
                    unsupported_features=unsupported_features,
                    solver_backend=solver_backend,
                    traffic_type=traffic_type,
                    generation_success=generation_success,
                )

            write_json(
                diagnose_path,
                {
                    "stage": "solve",
                    "reason": CONSTRAINT_UNSAT,
                    "unsat": plan["unsat_reasons"],
                    "http_status": status_code,
                    "result": asdict(result),
                },
            )
            return result
        except Exception as e:
            if capture_proc is not None:
                stop_capture(capture_proc)
            result = ValidationResult(
                sid=sid,
                msg=msg,
                status="MISS",
                miss_reason=CONSTRAINT_UNSAT,
                request_path=str(req_path),
                pcap_path=str(pcap_path),
                eve_path=str(eve_path),
                unsupported_features=unsupported_features,
                traffic_type=traffic_type,
                generation_success=False,
            )
            write_json(
                diagnose_path,
                {
                    "stage": "solve",
                    "reason": CONSTRAINT_UNSAT,
                    "unsat": plan["unsat_reasons"],
                    "error": str(e),
                    "result": asdict(result),
                },
            )
            return result

    capture_proc: Optional[subprocess.Popen] = None
    try:
        if adapter != "http":
            emit_info = {}
            capture_proc = start_capture(cfg, pcap_path)
            try:
                emit_info = emit_rule_payload(rule, cfg.target_server, timeout=int(cfg.request_timeout))
                req_path.write_bytes((emit_info.get("payload") or b""))
                time.sleep(cfg.post_request_sleep_seconds)
            finally:
                stop_capture(capture_proc)
                capture_proc = None

            skipped = emit_info.get("status") == "SKIPPED"
            produced_eve_path = eve_path
            hit = False
            if not skipped:
                hit, produced_eve_path = run_suricata_verify(cfg, pcap_path, rule_path, sid_dir / "suricata_out")
                if produced_eve_path.exists():
                    shutil.copy2(produced_eve_path, eve_path)

            emit_error = emit_info.get("emit_error")
            bytes_sent = int(emit_info.get("bytes_sent") or 0)
            payload = emit_info.get("payload") or b""
            generation_success = bool(payload) and bytes_sent > 0 and not emit_error and not skipped
            status = "SKIPPED" if skipped else ("HIT" if hit else "MISS")
            miss_reason = None
            if status == "MISS":
                miss_reason = EMIT_FAILED if emit_error else NO_ALERT_FOR_SID

            result = ValidationResult(
                sid=sid,
                msg=msg,
                status=status,
                skip_reason=emit_info.get("skip_reason") if skipped else None,
                miss_reason=miss_reason,
                request_path=str(req_path),
                pcap_path=str(pcap_path),
                eve_path=str(eve_path),
                unsupported_features=unsupported_features + list(emit_info.get("unsupported_transport_features") or []),
                solver_backend=adapter,
                traffic_type=traffic_type,
                generation_success=generation_success,
            )
            write_json(
                diagnose_path,
                {
                    "stage": "complete",
                    "adapter": adapter,
                    "hit": hit,
                    "warnings": emit_info.get("warnings") or [],
                    "target_port": emit_info.get("target_port"),
                    "transport": emit_info.get("transport"),
                    "qname": emit_info.get("qname"),
                    "qtype": emit_info.get("qtype"),
                    "opcode": emit_info.get("opcode"),
                    "unsupported_dns_features": emit_info.get("unsupported_dns_features") or [],
                    "bytes_sent": bytes_sent,
                    "emit_error": emit_error,
                    "generation_success_basis": {
                        "payload_non_empty": bool(payload),
                        "bytes_sent_gt_zero": bytes_sent > 0,
                        "emit_error_absent": not bool(emit_error),
                        "not_skipped": not skipped,
                    },
                    "generation_success": generation_success,
                    "emit_info": emit_info,
                    "result": asdict(result),
                },
            )
            return result

        tx_plan_obj = extract_http_plan(rule)
        default_host = cfg.target_server.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0] or "example.com"
        request_bytes = build_request(tx_plan_obj, default_host=default_host)
        solver_backend = "plan"
        req_path.write_bytes(request_bytes)

        capture_proc = start_capture(cfg, pcap_path)
        status_code, _ = send_raw_http_bytes(cfg.target_server, request_bytes, timeout=cfg.request_timeout)
        time.sleep(cfg.post_request_sleep_seconds)
        stop_capture(capture_proc)
        capture_proc = None

        strategy = classify_http_rule_strategy(rule.body.clauses)
        if should_try_legacy_fallback(strategy):
            hit, produced_eve_path, status_code, solver_backend = run_fallback_attempts(
                cfg=cfg,
                rule=rule,
                request_bytes=request_bytes,
                req_path=req_path,
                pcap_path=pcap_path,
                rule_path=rule_path,
                status_code=status_code,
            )
        else:
            hit, produced_eve_path = run_suricata_verify(cfg, pcap_path, rule_path, sid_dir / "suricata_out")

        if produced_eve_path.exists():
            shutil.copy2(produced_eve_path, eve_path)

        result = ValidationResult(
            sid=sid,
            msg=msg,
            status="PASS" if hit else "MISS",
            miss_reason=None if hit else NO_ALERT_FOR_SID,
            request_path=str(req_path),
            pcap_path=str(pcap_path),
            eve_path=str(eve_path),
            unsupported_features=unsupported_features,
            solver_backend=solver_backend,
            traffic_type=traffic_type,
            generation_success=True,
        )
        write_json(
            diagnose_path,
            {
                "stage": "complete",
                "http_status": status_code,
                "hit": hit,
                "request_path": str(req_path),
                "result": asdict(result),
            },
        )
        return result
    except Exception as e:
        if capture_proc is not None:
            stop_capture(capture_proc)
        message = str(e)
        reason = BUILD_REQUEST_FAILED
        low = message.lower()
        if "buffer_mapping_suspect" in low:
            reason = BUFFER_MAPPING_SUSPECT
        elif "skip_http_binary_unsafe" in low or "binary" in low:
            reason = UNSUPPORTED_BINARY_HTTP_FIELD
        elif "send_raw_http_bytes" in message or "invalid server url" in low:
            reason = EMIT_FAILED
        elif "suricata" in low:
            reason = SURICATA_FAILED
        elif "parse" in low and "http" in low:
            reason = HTTP_PARSE_SUSPECT
        result = ValidationResult(
            sid=sid,
            msg=msg,
            status="MISS",
            miss_reason=reason,
            request_path=str(req_path),
            pcap_path=str(pcap_path),
            eve_path=str(eve_path),
            unsupported_features=unsupported_features,
            traffic_type=traffic_type if 'traffic_type' in locals() else None,
            generation_success=False,
        )
        write_json(diagnose_path, {"stage": "exception", "error": message, "result": asdict(result)})
        return result


def main() -> None:
    cfg = load_config()
    validate_inputs(cfg)
    cfg.output_root.mkdir(parents=True, exist_ok=True)

    parsed_rules = parse_rules(cfg.dataset_path)
    selected = parsed_rules[: cfg.max_rules] if cfg.max_rules > 0 else parsed_rules
    total = len(selected)
    if total == 0:
        raise ValueError("No valid rules found in dataset")

    console(f"Pipeline starts. total={total}")
    results: list[ValidationResult] = []
    for idx, rule_ast in enumerate(selected, start=1):
        console("=" * 80)
        result = process_one_rule(cfg, rule_ast, idx, total)
        results.append(result)
        log_rule_result(idx, total, result)

    summary = {
        "total": total,
        "pass": sum(1 for x in results if x.status == "PASS"),
        "skipped": sum(1 for x in results if x.status == "SKIPPED"),
        "miss": sum(1 for x in results if x.status == "MISS"),
        "generation_success": sum(1 for x in results if x.generation_success is True),
        "generation_failed": sum(1 for x in results if x.generation_success is False),
        "results": [asdict(r) for r in results],
    }
    write_json(cfg.output_root / "results.json", summary)
    console(
        f"Done. pass={summary['pass']} skipped={summary['skipped']} "
        f"miss={summary['miss']} gen_ok={summary['generation_success']} "
        f"gen_fail={summary['generation_failed']}"
    )


if __name__ == "__main__":
    cfg = ValidationConfig(
        dataset_path=Path(r"E:\Develop\devpy\experiment\resources\dataset\converted_emerging-all_http_tcp_udp.rules"),
        target_server="http://192.168.1.199:80",
        output_root=Path(r"E:\Develop\devpy\experiment\resources\validation_run"),
        dumpcap_exe=Path(r"E:\Wireshark\dumpcap.exe"),
        capture_interface=r"\Device\NPF_{A4219C22-46C9-47A5-A0BD-50DC4B06644A}",
        suricata_exe=Path(r"C:\Program Files\Suricata\suricata.exe"),
        suricata_yaml=Path(r"C:\Program Files\Suricata\suricata.yaml"),
        capinfos_exe=Path(r"E:\Wireshark\capinfos.exe"),
        max_rules=100,
        request_timeout=3.0,
        capture_settle_seconds=1.0,
        post_request_sleep_seconds=2.0,
    )

    validate_inputs(cfg)
    cfg.output_root.mkdir(parents=True, exist_ok=True)

    parsed_rules = parse_rules(cfg.dataset_path)
    if not parsed_rules:
        raise ValueError("No valid rules found in dataset")

    if cfg.max_rules > 0:
        sample_size = min(cfg.max_rules, len(parsed_rules))
        selected = random.sample(parsed_rules, sample_size)
    else:
        selected = parsed_rules

    total = len(selected)

    console(f"Pipeline starts. total={total}")
    results: list[ValidationResult] = []
    for idx, rule_ast in enumerate(selected, start=1):
        console("=" * 80)
        result = process_one_rule(cfg, rule_ast, idx, total)
        results.append(result)
        log_rule_result(idx, total, result)

    summary = {
        "total": total,
        "pass": sum(1 for x in results if x.status == "PASS"),
        "skipped": sum(1 for x in results if x.status == "SKIPPED"),
        "miss": sum(1 for x in results if x.status == "MISS"),
        "generation_success": sum(1 for x in results if x.generation_success is True),
        "generation_failed": sum(1 for x in results if x.generation_success is False),
        "results": [asdict(r) for r in results],
    }
    write_json(cfg.output_root / "results.json", summary)
    console(
        f"Done. pass={summary['pass']} skipped={summary['skipped']} "
        f"miss={summary['miss']} gen_ok={summary['generation_success']} "
        f"gen_fail={summary['generation_failed']}"
    )

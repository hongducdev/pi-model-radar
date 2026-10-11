#!/usr/bin/env python3
"""pi-model-radar: Pi model discovery, cache, diffing, and health probing."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

MASK_PATTERN = re.compile(
    r'(?i)'
    r'(?P<kv>(?:["\'`]?\b(?:api[_-]?key|api_secret|access_token|secret_key|secret|token|password|auth|key)\b["\'`]?\s*[:=]\s*["\'`]?)(?P<kv_val>[^"\'`\s,;}{]+)(?P<kv_quote>["\'`]?))'
    r'|(?P<bearer>Bearer\s+(?P<bearer_val>[A-Za-z0-9_.-]+)\b(?!\*))'
    r'|(?P<sk>sk-[A-Za-z0-9_-]+\b(?!\*))'
    r'|(?P<long>[A-Za-z0-9_-]{32,}\b(?!\*))'
)


def mask_secrets(text: str) -> str:
    """Mask secrets keeping first 4 chars + '***'."""
    if not text:
        return "" if text == "" else text
    text = str(text)

    def _replace(m):
        if m.group('kv'):
            val = m.group('kv_val')
            if '*' in val:
                return m.group(0)
            prefix = m.group('kv')[:m.start('kv_val') - m.start('kv')]
            quote = m.group('kv_quote')
            return f"{prefix}{val[:4]}***{quote}"
        if m.group('bearer'):
            val = m.group('bearer_val')
            return f"Bearer {val[:4]}***"
        if m.group('sk'):
            val = m.group('sk')
            return f"{val[:4]}***"
        if m.group('long'):
            val = m.group('long')
            return f"{val[:4]}***"
        return m.group(0)

    return MASK_PATTERN.sub(_replace, text)


def pi_exe() -> str:
    """Resolve pi (pi.cmd on Windows) so no shell is needed."""
    return shutil.which('pi') or 'pi'


def get_report_path() -> Path:
    override = os.environ.get('PI_RADAR_REPORT')
    return Path(override) if override else Path.home() / '.pi' / 'agent' / 'pi-model-radar.json'


def get_settings_path() -> Path:
    override = os.environ.get('PI_SETTINGS_PATH')
    return Path(override) if override else Path.home() / '.pi' / 'agent' / 'settings.json'


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            try:
                os.unlink(name)
            except OSError:
                pass


def parse_context_tokens(val: str) -> int:
    val = (val or '').strip()
    if not val or val == '-':
        return 0
    mult = 1
    if val.endswith(('k', 'K')):
        mult = 1000
        val = val[:-1]
    elif val.endswith(('m', 'M')):
        mult = 1000000
        val = val[:-1]
    elif val.endswith(('g', 'G')):
        mult = 1000000000
        val = val[:-1]
    try:
        return int(round(float(val) * mult))
    except (ValueError, TypeError):
        return 0


def parse_models_table(text: str) -> list[dict]:
    lines = text.strip().splitlines()
    header_found = False
    models = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not header_found:
            lower_parts = [p.lower() for p in parts]
            if len(lower_parts) >= 6 and lower_parts[0] == 'provider' and lower_parts[1] == 'model':
                header_found = True
            continue

        if len(parts) < 6:
            continue
        if parts[0].startswith(('-', '=')):
            continue

        provider = parts[0]
        model = " ".join(parts[1:-4])
        context = parts[-4]
        max_out = parts[-3]
        thinking_str = parts[-2]
        images_str = parts[-1]

        thinking = thinking_str.lower() in ('yes', 'true', '1')
        images = images_str.lower() in ('yes', 'true', '1')
        context_tokens = parse_context_tokens(context)
        model_id = f"{provider}/{model}"

        models.append({
            "id": model_id,
            "provider": provider,
            "model": model,
            "context": context,
            "context_tokens": context_tokens,
            "max_out": max_out,
            "thinking": thinking,
            "images": images,
        })
    return models


def get_default_model(settings_path: Path) -> str | None:
    if not settings_path.is_file():
        return None
    name = settings_path.name
    if name == 'auth.json' or name.endswith('-keys.json') or name.endswith('-accounts.json'):
        raise PermissionError(f"Access to {name} is forbidden")
    try:
        with open(settings_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        prov = data.get('defaultProvider')
        mod = data.get('defaultModel')
        if prov and mod:
            return f"{prov}/{mod}"
    except (json.JSONDecodeError, OSError):
        pass
    return None


def calculate_diff(old_report: dict | None, current_models: list[dict], current_default: str | None) -> tuple[dict, dict]:
    current_ids = {m['id'] for m in current_models}
    if old_report is None:
        return {}, {
            "added": sorted(current_ids),
            "removed": [],
            "default_changed": None,
        }

    old_models = old_report.get('models', [])
    old_ids = {m['id'] for m in old_models if isinstance(m, dict) and 'id' in m}
    old_probes = old_report.get('probes', {})
    old_default = old_report.get('default')

    preserved_probes = {mid: p for mid, p in old_probes.items() if mid in current_ids}
    added = sorted(current_ids - old_ids)
    removed = sorted(old_ids - current_ids)

    default_changed = None
    if old_default != current_default:
        default_changed = {"from": old_default, "to": current_default}

    diff = {
        "added": added,
        "removed": removed,
        "default_changed": default_changed,
    }
    return preserved_probes, diff


def scan() -> int:
    cmd = [pi_exe(), "--list-models"]
    try:
        res = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        print(f"Error executing {' '.join(cmd)}: {exc}", file=sys.stderr)
        return 1

    if res.returncode != 0:
        err = mask_secrets(res.stderr or res.stdout)
        print(f"Error running 'pi --list-models': {err}", file=sys.stderr)
        return 1

    models = parse_models_table(res.stdout)
    default_model = get_default_model(get_settings_path())

    report_path = get_report_path()
    old_report = None
    if report_path.is_file():
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                old_report = json.load(f)
        except (json.JSONDecodeError, OSError):
            old_report = None

    preserved_probes, diff = calculate_diff(old_report, models, default_model)
    report = {
        "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "default": default_model,
        "models": models,
        "probes": preserved_probes,
        "diff": diff,
    }
    atomic_json(report_path, report)

    providers = {m['provider'] for m in models}
    diff_msg = f"+{len(diff['added'])} added, -{len(diff['removed'])} removed"
    if diff['default_changed']:
        diff_msg += f", default changed ({diff['default_changed']['from']} -> {diff['default_changed']['to']})"
    print(f"Scanned {len(models)} models ({len(providers)} providers). Default: {default_model or 'None'}.")
    print(f"Diff: {diff_msg}. Preserved probes: {len(preserved_probes)}.")
    return 0


def status() -> int:
    report_path = get_report_path()
    if not report_path.is_file():
        print(f"Error: no radar report found at {report_path}. Run 'scan' first.", file=sys.stderr)
        return 1

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error: could not read report at {report_path}: {exc}", file=sys.stderr)
        return 1

    scanned_at_str = report.get('scanned_at')
    if scanned_at_str:
        try:
            scanned_dt = dt.datetime.fromisoformat(scanned_at_str)
            now_dt = dt.datetime.now(dt.timezone.utc)
            age_hours = (now_dt - scanned_dt).total_seconds() / 3600.0
            print(f"Report age: {age_hours:.1f} hours ({scanned_at_str})")
        except ValueError:
            print(f"Report age: invalid timestamp ({scanned_at_str})")
    else:
        print("Report age: unknown")

    models = report.get('models', [])
    provider_counts: dict[str, int] = {}
    for m in models:
        p = m.get('provider', 'unknown')
        provider_counts[p] = provider_counts.get(p, 0) + 1
    prov_str = ", ".join(f"{k}: {v}" for k, v in sorted(provider_counts.items()))
    print(f"Models: {len(models)} total across {len(provider_counts)} providers ({prov_str})")

    print(f"Default: {report.get('default') or 'None'}")

    diff = report.get('diff', {})
    added = diff.get('added', [])
    removed = diff.get('removed', [])
    def_chg = diff.get('default_changed')
    diff_msg = f"+{len(added)} added, -{len(removed)} removed"
    if def_chg:
        diff_msg += f" (default: {def_chg.get('from')} -> {def_chg.get('to')})"
    print(f"Last diff: {diff_msg}")

    probes = report.get('probes', {})
    ok_count = sum(1 for p in probes.values() if p.get('ok'))
    fail_count = sum(1 for p in probes.values() if not p.get('ok'))
    print(f"Probes: {ok_count} ok, {fail_count} failed ({len(probes)} total)")
    return 0


def probe(model_id: str, timeout: int = 120) -> int:
    report_path = get_report_path()
    if not report_path.is_file():
        print(f"Error: no radar report found at {report_path}. Run 'scan' first.", file=sys.stderr)
        return 2

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"Error: failed to parse report at {report_path}.", file=sys.stderr)
        return 2

    models = report.get('models', [])
    known_ids = {m['id'] for m in models if isinstance(m, dict) and 'id' in m}
    if model_id not in known_ids:
        print(f"Error: model '{model_id}' is not in latest report models. Probe refused.", file=sys.stderr)
        return 2

    cmd = [pi_exe(), "-p", "reply with exactly: pong", "--model", model_id]
    start = time.perf_counter()
    ok = False
    error = None
    try:
        res = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        latency_s = round(time.perf_counter() - start, 3)
        stdout_lower = (res.stdout or "").lower()
        if res.returncode == 0 and "pong" in stdout_lower:
            ok = True
            error = None
        else:
            ok = False
            raw_err = res.stderr.strip() if res.stderr and res.stderr.strip() else res.stdout.strip()
            if not raw_err:
                raw_err = f"exit code {res.returncode}"
            error = mask_secrets(raw_err)[:300]
    except subprocess.TimeoutExpired:
        latency_s = round(time.perf_counter() - start, 3)
        ok = False
        error = f"Timeout after {timeout}s"
    except Exception as exc:
        latency_s = round(time.perf_counter() - start, 3)
        ok = False
        error = mask_secrets(str(exc))[:300]

    probe_record = {
        "ok": ok,
        "latency_s": latency_s,
        "at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "error": error,
    }

    if "probes" not in report or not isinstance(report["probes"], dict):
        report["probes"] = {}
    report["probes"][model_id] = probe_record
    atomic_json(report_path, report)

    status_desc = "ok" if ok else f"failed ({error})"
    print(f"Probe {model_id}: {status_desc} [{latency_s}s]")
    return 0 if ok else 1


def recommend() -> int:
    report_path = get_report_path()
    if not report_path.is_file():
        print(f"Error: no radar report found at {report_path}. Run 'scan' first.", file=sys.stderr)
        return 1

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"Error: failed to parse report at {report_path}.", file=sys.stderr)
        return 1

    models = report.get('models', [])
    probes = report.get('probes', {})
    default_id = report.get('default')

    ok_models = [m for m in models if probes.get(m['id'], {}).get('ok') is True]

    if not ok_models:
        print("No models have been verified with a successful probe.")
        if default_id:
            print(f"Suggest probing the default model first:\n  python scripts/radar.py probe --model {default_id}")
        else:
            print("Suggest running a probe on one of the scanned models.")
        return 0

    def sort_key(m):
        is_default = 1 if (default_id and m['id'] == default_id) else 0
        return (is_default, m.get('context_tokens', 0))

    sorted_models = sorted(ok_models, key=sort_key, reverse=True)

    print(f"Recommended models ({len(sorted_models)} probed ok):")
    for idx, m in enumerate(sorted_models, 1):
        is_def_str = " [DEFAULT]" if m['id'] == default_id else ""
        ctx = m.get('context', 'unknown')
        tokens = m.get('context_tokens', 0)
        lat = probes.get(m['id'], {}).get('latency_s', '?')
        print(f"  {idx}. {m['id']}{is_def_str} (context: {ctx} / {tokens:,} tokens, latency: {lat}s)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="pi-model-radar: Pi model scanner and prober")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("scan", help="Scan models via pi --list-models")
    subparsers.add_parser("status", help="Show report summary and age")

    probe_p = subparsers.add_parser("probe", help="Probe model responsiveness")
    probe_p.add_argument("--model", required=True, help="Model ID (provider/model)")
    probe_p.add_argument("--timeout", type=int, default=120, help="Probe timeout in seconds")

    subparsers.add_parser("recommend", help="Recommend verified models")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return scan()
    elif args.command == "status":
        return status()
    elif args.command == "probe":
        return probe(args.model, args.timeout)
    elif args.command == "recommend":
        return recommend()
    return 0


if __name__ == '__main__':
    sys.exit(main())

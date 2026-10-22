import ctypes
import hashlib
import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

BASE = Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
STATE_PATH = BASE / "state.json"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def windows_drives():
    """Return currently connected Windows removable-drive roots such as E:\\."""
    if platform.system() != "Windows":
        return set()
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    drives = set()
    for i in range(26):
        if mask & (1 << i):
            letter = chr(65 + i)
            root = f"{letter}:\\"
            dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
            if dtype == 2:  # DRIVE_REMOVABLE
                drives.add(root)
    return drives


def resolve_protected_directories(cfg):
    """Support both the old single-directory setting and the newer list setting."""
    raw = cfg.get("protected_directories")
    if not raw:
        raw = [cfg.get("protected_directory", "./protected-data")]
    if isinstance(raw, str):
        raw = [raw]

    result = []
    for value in raw:
        p = Path(value)
        if not p.is_absolute():
            p = BASE / p
        p = p.resolve()
        p.mkdir(parents=True, exist_ok=True)
        result.append(p)
    return result


def risk_score(history):
    recent = history[-50:]
    if not recent:
        return 0, "LOW"

    counts = {}
    for item in recent:
        event_type = item.get("type", "UNKNOWN")
        counts[event_type] = counts.get(event_type, 0) + 1

    features = [[
        len(recent),
        counts.get("USB_CONNECTED", 0),
        counts.get("TAMPER_DETECTED", 0),
        counts.get("DATA_EXFILTRATION_ATTEMPT", 0),
    ]]

    ml_score = 0
    if ML_AVAILABLE and len(recent) >= 5:
        training = []
        for i in range(max(0, len(recent) - 20), len(recent)):
            part = recent[max(0, i - 4): i + 1]
            c = {}
            for x in part:
                t = x.get("type", "UNKNOWN")
                c[t] = c.get(t, 0) + 1
            training.append([
                len(part),
                c.get("USB_CONNECTED", 0),
                c.get("TAMPER_DETECTED", 0),
                c.get("DATA_EXFILTRATION_ATTEMPT", 0),
            ])
        if len(training) >= 5:
            model = IsolationForest(contamination="auto", random_state=42)
            model.fit(training)
            anomaly = model.decision_function(features)[0]
            ml_score = max(0, min(100, int(50 - anomaly * 100)))

    rule_score = min(
        100,
        counts.get("DATA_EXFILTRATION_ATTEMPT", 0) * 40
        + counts.get("TAMPER_DETECTED", 0) * 30
        + counts.get("USB_CONNECTED", 0) * 10,
    )
    score = max(rule_score, ml_score)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def send_event(cfg, state, event_type, severity, message, metadata=None):
    item = {
        "type": event_type,
        "severity": severity,
        "message": message,
        "metadata": metadata or {},
        "timestamp": now_iso(),
    }
    state["history"].append(item)
    state["history"] = state["history"][-int(cfg.get("risk_history_size", 50)):]
    score, level = risk_score(state["history"])
    item["metadata"]["aiRiskScore"] = score
    item["metadata"]["aiRiskLevel"] = level
    save_json(STATE_PATH, state)

    headers = {
        "x-agent-key": cfg["agent_key"],
        "content-type": "application/json",
    }
    payload = {
        "ownerEmail": cfg["owner_email"],
        "agentName": platform.node() or "SecureTracer-Agent",
        "platform": platform.platform(),
        "type": event_type,
        "severity": severity,
        "message": message,
        "metadata": item["metadata"],
        "timestamp": item["timestamp"],
    }
    try:
        r = requests.post(
            f"{cfg['api_url'].rstrip('/')}/agent/events",
            json=payload,
            headers=headers,
            timeout=5,
        )
        print(f"[{severity}] {message} | AI Risk {score}% ({level}) | API {r.status_code}")
    except Exception as exc:
        print(f"[{severity}] {message} | AI Risk {score}% ({level}) | API offline: {exc}")


def protected_files(directories):
    result = {}
    for directory in directories:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        for p in directory.rglob("*"):
            if p.is_file():
                try:
                    result[str(p.resolve())] = sha256_file(p)
                except (OSError, PermissionError):
                    pass
    return result


def scan_removable_for_exfiltration(drives, baseline):
    """Find a protected file copied to a removable drive by matching its SHA-256."""
    matches = []
    target_hashes = set(baseline.values())
    if not target_hashes:
        return matches

    for drive in drives:
        root = Path(drive)
        try:
            for p in root.rglob("*"):
                if p.is_file():
                    try:
                        h = sha256_file(p)
                        if h in target_hashes:
                            matches.append((str(p), h))
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    return matches


def main():
    if not CONFIG_PATH.exists():
        print("Missing config.json. Copy config.example.json to config.json and edit it.")
        return

    cfg = load_json(CONFIG_PATH, {})
    required = ["api_url", "agent_key", "owner_email"]
    missing = [key for key in required if not cfg.get(key)]
    if missing:
        print("Missing config values: " + ", ".join(missing))
        return

    protected_dirs = resolve_protected_directories(cfg)
    state = load_json(
        STATE_PATH,
        {"baseline": {}, "drives": [], "history": [], "startedAt": now_iso()},
    )

    print("SecureTracer Security Agent started")
    print("Protected directories:")
    for directory in protected_dirs:
        print(f"  - {directory}")
    print(f"AI engine: {'Isolation Forest' if ML_AVAILABLE else 'rule fallback'}")
    print("USB monitoring: Windows removable drives")
    print("Press Ctrl+C to stop the agent.")

    # Create the initial baseline. Existing protected files are considered trusted at startup.
    state["baseline"] = protected_files(protected_dirs)
    state["drives"] = sorted(windows_drives())
    state["usb_matches"] = []
    save_json(STATE_PATH, state)
    send_event(
        cfg,
        state,
        "AGENT_ONLINE",
        "LOW",
        "SecureTracer endpoint agent is online",
        {"protectedFiles": len(state["baseline"]), "protectedDirectories": [str(p) for p in protected_dirs]},
    )

    last_usb_scan = 0
    last_match_set = set()

    try:
        while True:
            time.sleep(max(1, int(cfg.get("scan_interval_seconds", 3))))

            # File integrity monitoring.
            current = protected_files(protected_dirs)
            baseline = state.get("baseline", {})
            for filename, old_hash in list(baseline.items()):
                if filename not in current:
                    send_event(
                        cfg, state, "PROTECTED_FILE_REMOVED", "CRITICAL",
                        f"Protected file removed: {Path(filename).name}",
                        {"path": filename, "expectedHash": old_hash},
                    )
                elif current[filename] != old_hash:
                    send_event(
                        cfg, state, "TAMPER_DETECTED", "CRITICAL",
                        f"Protected file changed: {Path(filename).name}",
                        {"path": filename, "expectedHash": old_hash, "currentHash": current[filename]},
                    )
            for filename, new_hash in current.items():
                if filename not in baseline:
                    send_event(
                        cfg, state, "PROTECTED_FILE_ADDED", "LOW",
                        f"New protected file baseline created: {Path(filename).name}",
                        {"path": filename, "hash": new_hash},
                    )
            state["baseline"] = current
            save_json(STATE_PATH, state)

            # USB connection/disconnection monitoring.
            drives = windows_drives()
            old_drives = set(state.get("drives", []))
            for drive in sorted(drives - old_drives):
                send_event(
                    cfg, state, "USB_CONNECTED", "HIGH",
                    f"Removable USB device connected: {drive}",
                    {"drive": drive, "enforcementMode": cfg.get("enforcement_mode", "alert-only")},
                )
            for drive in sorted(old_drives - drives):
                send_event(
                    cfg, state, "USB_DISCONNECTED", "LOW",
                    f"Removable USB device disconnected: {drive}",
                    {"drive": drive},
                )
            state["drives"] = sorted(drives)
            save_json(STATE_PATH, state)

            # Scan USB contents periodically. Matching the protected file hash tells us
            # that the protected file itself was copied; it does not claim every possible
            # Windows copy route is blocked.
            if drives and time.time() - last_usb_scan > 10 and baseline:
                last_usb_scan = time.time()
                matches = scan_removable_for_exfiltration(drives, baseline)
                current_match_set = {(path, h) for path, h in matches}
                for copied_path, matched_hash in matches:
                    if (copied_path, matched_hash) in last_match_set:
                        continue
                    send_event(
                        cfg, state, "DATA_EXFILTRATION_ATTEMPT", "CRITICAL",
                        f"Protected-file copy detected on removable media: {Path(copied_path).name}",
                        {
                            "destination": copied_path,
                            "sha256": matched_hash,
                            "action": "ALERTED",
                            "enforcementMode": cfg.get("enforcement_mode", "alert-only"),
                        },
                    )
                last_match_set = current_match_set

    except KeyboardInterrupt:
        print("\nSecureTracer Security Agent stopped.")


if __name__ == "__main__":
    main()

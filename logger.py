# logger.py
# SentinelShield - Logger & Alert System
# Records all detections and generates alerts

import json
import os
from datetime import datetime

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
LOG_FILE   = "logs/alerts.log"
ALERT_FILE = "logs/alerts_summary.json"

# ─────────────────────────────────────────
# ENSURE LOG DIRECTORY EXISTS
# ─────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

# ─────────────────────────────────────────
# CORE LOGGING FUNCTION
# ─────────────────────────────────────────
def log_event(ip, method, path, body, detections, action, reason=""):
    """
    Logs a single request event to the log file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_types = ", ".join(detections) if detections else "None"

    log_entry = (
        f"[{timestamp}] "
        f"IP={ip} | "
        f"METHOD={method} | "
        f"PATH={path} | "
        f"BODY={body or 'None'} | "
        f"ATTACKS={attack_types} | "
        f"ACTION={action} | "
        f"REASON={reason or 'N/A'}"
    )

    # Write to log file
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

    # Print alert to terminal for visibility
    if action == "BLOCKED":
        print(f"\n  🚨 ALERT  | {timestamp}")
        print(f"     IP     : {ip}")
        print(f"     Path   : {method} {path}")
        print(f"     Attacks: {attack_types}")
        print(f"     Action : {action}")
        print(f"     Reason : {reason or 'Malicious content detected'}")
    else:
        print(f"\n  ✅ ALLOWED | {timestamp} | IP={ip} | {method} {path}")


# ─────────────────────────────────────────
# SUMMARY GENERATOR
# ─────────────────────────────────────────
def generate_summary():
    """
    Reads the log file and generates a JSON summary
    of all attacks, IPs, and categories.
    """
    if not os.path.exists(LOG_FILE):
        print("  No log file found.")
        return

    summary = {
        "total_requests" : 0,
        "total_blocked"  : 0,
        "total_allowed"  : 0,
        "attack_counts"  : {},
        "flagged_ips"    : {},
        "generated_at"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(LOG_FILE, "r") as f:
        for line in f:
            summary["total_requests"] += 1

            # Parse ACTION
            if "ACTION=BLOCKED" in line:
                summary["total_blocked"] += 1
            elif "ACTION=ALLOWED" in line:
                summary["total_allowed"] += 1

            # Parse ATTACKS
            try:
                attacks_part = line.split("ATTACKS=")[1].split("|")[0].strip()
                if attacks_part != "None":
                    for attack in attacks_part.split(","):
                        attack = attack.strip()
                        summary["attack_counts"][attack] = (
                            summary["attack_counts"].get(attack, 0) + 1
                        )
            except IndexError:
                pass

            # Parse IP
            try:
                ip = line.split("IP=")[1].split("|")[0].strip()
                if "ACTION=BLOCKED" in line:
                    summary["flagged_ips"][ip] = (
                        summary["flagged_ips"].get(ip, 0) + 1
                    )
            except IndexError:
                pass

    # Save summary to JSON
    with open(ALERT_FILE, "w") as f:
        json.dump(summary, f, indent=4)

    print("\n" + "="*55)
    print("   SentinelShield — Alert Summary")
    print("="*55)
    print(f"  Total Requests : {summary['total_requests']}")
    print(f"  Total Blocked  : {summary['total_blocked']}")
    print(f"  Total Allowed  : {summary['total_allowed']}")
    print(f"\n  Attack Breakdown:")
    for attack, count in summary["attack_counts"].items():
        print(f"    - {attack}: {count}")
    print(f"\n  Flagged IPs:")
    for ip, count in summary["flagged_ips"].items():
        print(f"    - {ip}: {count} blocked requests")
    print("="*55)

    return summary


# ─────────────────────────────────────────
# QUICK SELF-TEST
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("   SentinelShield — Logger Self Test")
    print("="*55)

    log_event("192.168.1.10", "GET",  "/home",                  None,          [],                       "ALLOWED")
    log_event("10.0.0.99",    "GET",  "/search?q=' OR 1=1--",   None,          ["SQL Injection"],         "BLOCKED")
    log_event("10.0.0.99",    "GET",  "/page?url=<script>",     None,          ["XSS"],                   "BLOCKED")
    log_event("172.16.0.5",   "GET",  "/files?path=../../etc",  None,          ["LFI","Directory Traversal"], "BLOCKED")
    log_event("10.0.0.99",    "POST", "/login",                  "cmd=whoami", ["Command Injection"],     "BLOCKED", "Rate limit exceeded")

    print("\n")
    generate_summary()

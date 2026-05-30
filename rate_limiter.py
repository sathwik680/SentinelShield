# rate_limiter.py
# SentinelShield - Rate Limiter
# Tracks IP-based request frequency and flags abusive IPs

import time
from collections import defaultdict

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
MAX_REQUESTS  = 10   # Max requests allowed
TIME_WINDOW   = 60   # In seconds (1 minute window)

# ─────────────────────────────────────────
# IP TRACKER STORAGE
# ─────────────────────────────────────────
ip_tracker = defaultdict(list)  # { "ip": [timestamp1, timestamp2, ...] }
blocked_ips = set()             # IPs that are permanently blocked

# ─────────────────────────────────────────
# CORE RATE CHECK FUNCTION
# ─────────────────────────────────────────
def check_rate_limit(ip):
    """
    Checks if an IP has exceeded the request threshold.
    Returns a dict with status and request count.
    """
    now = time.time()

    # Remove timestamps outside the time window
    ip_tracker[ip] = [
        t for t in ip_tracker[ip]
        if now - t < TIME_WINDOW
    ]

    # Add current request timestamp
    ip_tracker[ip].append(now)

    request_count = len(ip_tracker[ip])

    # Check if IP is already blocked
    if ip in blocked_ips:
        return {
            "ip"           : ip,
            "request_count": request_count,
            "status"       : "BLOCKED",
            "reason"       : "IP permanently blocked due to abuse",
        }

    # Check if IP exceeded threshold
    if request_count > MAX_REQUESTS:
        blocked_ips.add(ip)
        return {
            "ip"           : ip,
            "request_count": request_count,
            "status"       : "BLOCKED",
            "reason"       : f"Rate limit exceeded ({request_count} requests in {TIME_WINDOW}s)",
        }

    return {
        "ip"           : ip,
        "request_count": request_count,
        "status"       : "ALLOWED",
        "reason"       : f"{request_count}/{MAX_REQUESTS} requests used",
    }


def get_blocked_ips():
    """Returns the list of all currently blocked IPs."""
    return list(blocked_ips)


def reset_ip(ip):
    """Manually unblock an IP (admin action)."""
    blocked_ips.discard(ip)
    ip_tracker[ip] = []


# ─────────────────────────────────────────
# QUICK SELF-TEST
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("   SentinelShield — Rate Limiter Self Test")
    print("="*55)

    test_ip_normal    = "192.168.1.10"
    test_ip_attacker  = "10.0.0.99"

    print("\n--- Normal User (5 requests) ---")
    for i in range(5):
        result = check_rate_limit(test_ip_normal)
        print(f"  Request {i+1}: {result['status']} | {result['reason']}")

    print("\n--- Attacker IP (15 rapid requests) ---")
    for i in range(15):
        result = check_rate_limit(test_ip_attacker)
        print(f"  Request {i+1}: {result['status']} | {result['reason']}")

    print(f"\n  Blocked IPs: {get_blocked_ips()}")
    print("\n" + "="*55)

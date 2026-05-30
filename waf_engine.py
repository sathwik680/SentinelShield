# waf_engine.py
# SentinelShield - WAF Rule Engine
# Detects common web attack patterns in HTTP requests

import re

# ─────────────────────────────────────────
# ATTACK SIGNATURES (Rules Database)
# ─────────────────────────────────────────
RULES = {
    "SQL Injection": [
        r"(?i)(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b)",
        r"(?i)(--|;|'|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)",
        r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    ],
    "XSS": [
        r"(?i)<\s*script.*?>",
        r"(?i)(javascript\s*:|onerror\s*=|onload\s*=|onclick\s*=)",
        r"(?i)<\s*img.*?src\s*=.*?>",
        r"(?i)(alert\s*\(|document\.cookie|window\.location)",
    ],
    "LFI": [
        r"(?i)(\.\.\/|\.\.\\)",
        r"(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/self)",
        r"(?i)(php://filter|php://input|expect://)",
    ],
    "Command Injection": [
        r"(?i)(\||;|&&|\$\(|`)",
        r"(?i)(cat\s+\/|ls\s+-|whoami|id\s|uname|wget\s|curl\s)",
        r"(?i)(nc\s|netcat|bash\s+-i|\/bin\/sh|\/bin\/bash)",
    ],
    "Directory Traversal": [
        r"(?i)(\.\.\/){2,}",
        r"(?i)(%2e%2e%2f|%2e%2e\/|\.\.%2f)",
        r"(?i)(\/var\/www|\/home\/\w+|\/root\/)",
    ],
}

# ─────────────────────────────────────────
# CORE DETECTION FUNCTION
# ─────────────────────────────────────────
def inspect_request(method, path, headers=None, body=None):
    """
    Inspects all parts of an HTTP request.
    Returns a dict with detection results.
    """
    # Combine all request parts into one string for scanning
    target = f"{method} {path}"
    if headers:
        target += " " + " ".join(str(v) for v in headers.values())
    if body:
        target += " " + body

    detections = []

    for attack_type, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, target):
                detections.append(attack_type)
                break  # One match per category is enough

    result = {
        "method"    : method,
        "path"      : path,
        "body"      : body or "",
        "detections": list(set(detections)),  # remove duplicates
        "is_malicious": len(detections) > 0,
        "action"    : "BLOCKED" if detections else "ALLOWED",
    }

    return result


# ─────────────────────────────────────────
# QUICK SELF-TEST (run this file directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    test_cases = [
        ("GET",  "/search?q=hello world",                    None, None),
        ("GET",  "/search?q=' OR 1=1--",                     None, None),
        ("GET",  "/page?url=<script>alert(1)</script>",       None, None),
        ("GET",  "/files?path=../../etc/passwd",              None, None),
        ("POST", "/login",  None, "username=admin&cmd=whoami"),
        ("GET",  "/index.php?file=php://filter/convert",      None, None),
    ]

    print("\n" + "="*55)
    print("   SentinelShield — WAF Engine Self Test")
    print("="*55)

    for method, path, headers, body in test_cases:
        result = inspect_request(method, path, headers, body)
        status = f"[{result['action']}]"
        attacks = ", ".join(result["detections"]) if result["detections"] else "None"
        print(f"\n  Request : {method} {path}")
        print(f"  Body    : {body or 'None'}")
        print(f"  Status  : {status}")
        print(f"  Attacks : {attacks}")
    print("\n" + "="*55)



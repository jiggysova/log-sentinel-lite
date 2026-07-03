import re
from collections import defaultdict


def analyze_logs(log_file_path):
    failed_logins = defaultdict(int)

    with open(log_file_path, "r") as file:
        for line in file:
            if "LOGIN FAILED" in line:
                ip_match = re.search(
                    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    line
                )

                if ip_match:
                    ip_address = ip_match.group()
                    failed_logins[ip_address] += 1

    findings = []

    for ip, count in failed_logins.items():
        if count >= 4:
            risk_level = "High"
            alert = "Possible brute-force attack"

        elif count >= 3:
            risk_level = "Medium"
            alert = "Suspicious repeated failed logins"

        else:
            risk_level = "Low"
            alert = "Failed login activity observed"

        findings.append({
            "ip_address": ip,
            "failed_attempts": count,
            "risk_level": risk_level,
            "alert": alert
        })

    return findings
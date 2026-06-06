import re
import csv
import os
import matplotlib.pyplot as plt
from collections import Counter, defaultdict


# CREATE OUTPUT FOLDER

if not os.path.exists("outputs"):
    os.makedirs("outputs")


# PATTERNS

SQL_PATTERNS = ["or 1=1", "union select", "--", "drop table"]

XSS_PATTERNS = ["<script>", "javascript:", "onerror="]

SCAN_PATHS = ["/admin", "/phpmyadmin", "/wp-admin", "/.env"]


# STORAGE

attack_counts = Counter()
threat_scores = defaultdict(int)
failed_logins = defaultdict(int)
url_counter = Counter()
timeline = []
report_rows = []


# LOG PATTERN

log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(GET|POST).*? (.*?) HTTP.*?" (\d{3})'
)


# RISK FUNCTION

def get_risk(score):
    if score >= 20:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    return "LOW"


# READ LOG FILE

with open("access.log", "r") as file:

    for line in file:

        match = log_pattern.search(line)

        if not match:
            continue

        ip = match.group(1)
        timestamp = match.group(2)
        method = match.group(3)
        url = match.group(4)
        status = match.group(5)

        url_counter[url] += 1

        # -- SQLI
        for pattern in SQL_PATTERNS:
            if pattern in url.lower():
                attack_counts["SQLI"] += 1
                threat_scores[ip] += 10
                timeline.append((timestamp, ip, "SQLI"))
                report_rows.append([ip, "SQLI", url, "HIGH"])

        #XSS
        for pattern in XSS_PATTERNS:
            if pattern in url.lower():
                attack_counts["XSS"] += 1
                threat_scores[ip] += 8
                timeline.append((timestamp, ip, "XSS"))
                report_rows.append([ip, "XSS", url, "HIGH"])

        # BRUTE FORCE 
        if status == "401":
            failed_logins[ip] += 1

            if failed_logins[ip] >= 3:
                attack_counts["BRUTE_FORCE"] += 1
                threat_scores[ip] += 6
                timeline.append((timestamp, ip, "BRUTE_FORCE"))
                report_rows.append([ip, "BRUTE_FORCE", url, "MEDIUM"])

        # SCANNER 
        for path in SCAN_PATHS:
            if path in url.lower():
                attack_counts["SCANNER"] += 1
                threat_scores[ip] += 3
                timeline.append((timestamp, ip, "SCANNER"))
                report_rows.append([ip, "SCANNER", url, "LOW"])


# REPORT OUTPUT
print("\n=== ATTACK REPORT ===\n")

for attack, count in attack_counts.items():
    print(attack, ":", count)

print("\n=== TOP ATTACKERS ===\n")

for ip, score in sorted(threat_scores.items(), key=lambda x: x[1], reverse=True):
    print(ip, "Score:", score, "Risk:", get_risk(score))

print("\n=== TIMELINE ===\n")

for event in timeline:
    print(event)


# CSV REPORT

with open("outputs/report.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Attack", "URL", "Severity"])
    writer.writerows(report_rows)


# TXT REPORT

with open("outputs/report.txt", "w") as f:
    f.write("ATTACK INVESTIGATION REPORT\n\n")

    for attack, count in attack_counts.items():
        f.write(f"{attack}: {count}\n")

    f.write("\nTOP ATTACKERS\n\n")

    for ip, score in sorted(threat_scores.items(), key=lambda x: x[1], reverse=True):
        f.write(f"{ip} Score:{score} Risk:{get_risk(score)}\n")


# GRAPH

labels = list(attack_counts.keys())
values = list(attack_counts.values())
plt.figure(figsize=(8, 5))
plt.bar(labels, values)
plt.title("Attack Types")
plt.savefig("outputs/attacks.png")

print("\nReports generated in /outputs folder")
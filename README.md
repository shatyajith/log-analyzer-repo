 log-analyzer
Python-based security log analyzer that scans web server access logs and identifies SQL injection attempts, XSS attacks, brute-force login attempts, and directory scanning
Features:
Detects common SQL Injection patterns
Detects basic XSS attack attempts
Identifies repeated failed login attempts (brute force)
Detects reconnaissance/scanning activity
Assigns threat scores to attacking IP addresses
Generates attack timelines
Exports findings to CSV and TXT reports
Creates a visual summary chart of attack types

How It Works

The analyzer reads a web server access log and extracts:

Source IP address
Timestamp
HTTP method
Requested URL
Response status code

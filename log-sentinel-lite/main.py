from detector import analyze_logs
from reporter import generate_csv_report


log_file = 'logs/sample.log'
report_file = "reports/findings.csv"

findings = analyze_logs(log_file)

print("Log Sentinel Security Report")
print("============================")

for finding in findings:
    print(f"IP Address: {finding['ip_address']}")
    print(f"Failed Attempts: {finding['failed_attempts']}")
    print(f"Risk Level: {finding['risk_level']}")
    print(f"Alert: {finding['alert']}")
    print()

generate_csv_report(findings, report_file)
print(f"Report generated successfully: {report_file}")

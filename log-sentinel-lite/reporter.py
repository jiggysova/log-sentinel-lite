import csv


def generate_csv_report(findings, output_file_path):
    with open(output_file_path, "w", newline="") as file:
        fieldnames = [
            "ip_address",
            "failed_attempts",
            "risk_level",
            "alert"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(findings)
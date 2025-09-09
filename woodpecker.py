#!/usr/bin/env python3
"""
🪵 Woodpecker – AWS Inventory & Audit Tool
Author: gbalaji
Version: 1.1
Description: Enumerates AWS services, resources, URLs, and optionally runs Prowler scans.
Generates a professional HTML report.
"""

import subprocess, json, datetime, sys, os

TOOL_NAME = "Woodpecker"

# -------- Logging --------
def log(msg): print(f"[{TOOL_NAME}] {msg}")

# -------- AWS CLI Call --------
def aws_cli(cmd):
    try:
        result = subprocess.check_output(f"aws {cmd}", shell=True, stderr=subprocess.DEVNULL)
        return json.loads(result.decode())
    except Exception as e:
        log(f"Error running AWS CLI '{cmd}': {e}")
        return {}

# -------- Enumerate Services --------
def enum_services():
    log("Enumerating AWS services...")
    services = {}
    
    # Example: S3 Buckets
    s3 = aws_cli("s3api list-buckets")
    buckets = []
    for b in s3.get("Buckets", []):
        url = f"https://{b['Name']}.s3.amazonaws.com"
        buckets.append({"Name": b["Name"], "URL": url})
    services["S3"] = buckets

    # Example: EC2 Instances
    ec2 = aws_cli("ec2 describe-instances")
    instances = []
    for res in ec2.get("Reservations", []):
        for inst in res.get("Instances", []):
            name = next((tag['Value'] for tag in inst.get("Tags", []) if tag["Key"]=="Name"), inst["InstanceId"])
            instances.append({"Name": name, "ID": inst["InstanceId"]})
    services["EC2"] = instances

    # Example: CloudFront distributions
    cf = aws_cli("cloudfront list-distributions")
    distributions = []
    for d in cf.get("DistributionList", {}).get("Items", []):
        distributions.append({"ID": d["Id"], "DomainName": d["DomainName"]})
    services["CloudFront"] = distributions

    # Add more AWS services here as needed

    return services

# -------- Generate HTML Table --------
def html_table(title, items):
    table = f"<h2>{title}</h2><table border='1' cellpadding='5'><tr>"
    if items:
        headers = items[0].keys()
        table += "".join([f"<th>{h}</th>" for h in headers])
        table += "</tr>"
        for i in items:
            table += "<tr>" + "".join([f"<td>{i[h]}</td>" for h in headers]) + "</tr>"
    else:
        table += "<tr><td>No resources found</td></tr>"
    table += "</table>"
    return table

# -------- Generate HTML Report --------
def generate_report(results, prowler, fname):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"Generating HTML report: {fname}")
    html = f"<html><head><title>{TOOL_NAME} Report</title></head><body>"
    html += f"<h1>{TOOL_NAME} Report</h1><p>Generated: {ts}</p>"

    for svc, items in results.items():
        html += html_table(svc, items)

    if prowler:
        html += "<h2>Prowler Findings</h2><pre>"
        html += json.dumps(prowler, indent=4)
        html += "</pre>"

    html += "</body></html>"

    with open(fname, "w") as f:
        f.write(html)

    log(f"Report saved as {fname}")

# -------- Optional Prowler Scan --------
def run_prowler(services=None):
    log("Running Prowler scan (optional)...")
    cmd = "prowler -M json"
    if services:
        cmd += " -c " + ",".join(services)
    try:
        result = subprocess.check_output(cmd, shell=True)
        return json.loads(result.decode())
    except Exception as e:
        log(f"Prowler scan failed: {e}")
        return {}

# -------- Main Execution --------
def main():
    log("Welcome to Woodpecker AWS Inventory Tool")
    choice = input("Scan (1) Entire Account or (2) Specific Stack? [1/2]: ").strip()
    stack_name = ""
    if choice == "2":
        stack_name = input("Enter CloudFormation stack name: ").strip()
        log(f"Stack scan selected: {stack_name}")

    report_name = input("Enter HTML report filename (e.g., report.html): ").strip()
    if not report_name.endswith(".html"):
        report_name += ".html"

    results = enum_services()
    
    prowler_choice = input("Run Prowler security scan? [y/N]: ").strip().lower()
    prowler_results = None
    if prowler_choice == "y":
        specific = input("Scan all services or specific ones? [all/specific]: ").strip().lower()
        srv_list = None
        if specific == "specific":
            srv_list = input("Enter comma-separated service names: ").strip().split(",")
        prowler_results = run_prowler(srv_list)

    generate_report(results, prowler_results, report_name)
    log("Woodpecker scan completed!")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
🪵 Woodpecker — AWS Inventory & Audit Tool
Author: gbalaji + ChatGPT
Description:
    - Enumerates AWS services using AWS CLI
    - Supports Account Scan & Stack Scan modes
    - Lists resources with URLs/endpoints
    - Optional Prowler scan
    - Generates HTML report
"""

import subprocess, json, sys, datetime

TOOL_NAME = "Woodpecker"

# -------------------------------
# Helpers
# -------------------------------
def log(msg):
    """Console log helper."""
    print(f"[+] {msg}")

def run_cli(cmd):
    """Run AWS CLI command and return JSON."""
    try:
        out = subprocess.check_output(cmd, text=True)
        return json.loads(out) if out.strip().startswith(("{","[")) else out.strip()
    except Exception:
        return None

def html_table(service, items):
    """Convert list of dicts to HTML table."""
    if not items: return ""
    headers = items[0].keys()
    html = f"<h2>{service}</h2><table border='1'><tr>"
    html += "".join(f"<th>{h}</th>" for h in headers) + "</tr>"
    for row in items:
        html += "<tr>"
        for v in row.values():
            if isinstance(v,str) and v.startswith("http"):
                html += f"<td><a href='{v}' target='_blank'>{v}</a></td>"
            else:
                html += f"<td>{v}</td>"
        html += "</tr>"
    return html + "</table>"

# -------------------------------
# Enumerators
# -------------------------------
def get_s3():
    log("Enumerating S3 buckets...")
    data = run_cli(["aws","s3api","list-buckets","--output","json"])
    out=[]
    for b in data.get("Buckets",[]):
        name = b["Name"]
        loc = run_cli(["aws","s3api","get-bucket-location","--bucket",name,"--output","json"])
        region = loc.get("LocationConstraint") or "us-east-1"
        url = f"https://{name}.s3.{region}.amazonaws.com/"
        out.append({"Name":name,"Region":region,"URL":url})
    log(f"Found {len(out)} S3 buckets")
    return ("S3 Buckets",out)

def get_cloudfront():
    log("Enumerating CloudFront distributions...")
    data = run_cli(["aws","cloudfront","list-distributions","--output","json"])
    items = data.get("DistributionList",{}).get("Items",[]) if data else []
    out = [{"ID":d["Id"],"Domain":d["DomainName"],"Status":d["Status"]} for d in items]
    log(f"Found {len(out)} CloudFront distributions")
    return ("CloudFront Distributions",out)

def get_ec2():
    log("Enumerating EC2 instances...")
    data = run_cli(["aws","ec2","describe-instances","--output","json"])
    out=[]
    for r in data.get("Reservations",[]):
        for i in r["Instances"]:
            out.append({"ID":i["InstanceId"],"Type":i["InstanceType"],"DNS":i.get("PublicDnsName","N/A")})
    log(f"Found {len(out)} EC2 instances")
    return ("EC2 Instances",out)

def get_rds():
    log("Enumerating RDS instances...")
    data = run_cli(["aws","rds","describe-db-instances","--output","json"])
    out=[{"ID":d["DBInstanceIdentifier"],"Engine":d["Engine"],"Endpoint":d["Endpoint"]["Address"]}
         for d in data.get("DBInstances",[])]
    log(f"Found {len(out)} RDS databases")
    return ("RDS Databases",out)

def get_lambda():
    log("Enumerating Lambda functions...")
    data = run_cli(["aws","lambda","list-functions","--output","json"])
    out=[{"Name":f["FunctionName"],"Runtime":f["Runtime"],
          "Console":f"https://console.aws.amazon.com/lambda/home#/functions/{f['FunctionName']}"}
         for f in data.get("Functions",[])]
    log(f"Found {len(out)} Lambda functions")
    return ("Lambda Functions",out)

def get_dynamo():
    log("Enumerating DynamoDB tables...")
    data = run_cli(["aws","dynamodb","list-tables","--output","json"])
    out=[{"Name":t,"Console":f"https://console.aws.amazon.com/dynamodb/home#tables:selected={t}"} 
         for t in data.get("TableNames",[])]
    log(f"Found {len(out)} DynamoDB tables")
    return ("DynamoDB Tables",out)

def get_apigw():
    log("Enumerating API Gateways...")
    data = run_cli(["aws","apigateway","get-rest-apis","--output","json"])
    out=[{"Name":a["Name"],"ID":a["Id"],
          "URL":f"https://{a['Id']}.execute-api.us-east-1.amazonaws.com"} for a in data.get("items",[])]
    log(f"Found {len(out)} API Gateways")
    return ("API Gateways",out)

def get_elb():
    log("Enumerating Load Balancers...")
    data = run_cli(["aws","elbv2","describe-load-balancers","--output","json"])
    out=[{"Name":lb["LoadBalancerName"],"DNS":lb["DNSName"],"Type":lb["Type"]}
         for lb in data.get("LoadBalancers",[])]
    log(f"Found {len(out)} Load Balancers")
    return ("Load Balancers",out)

SERVICES = [get_s3,get_cloudfront,get_ec2,get_rds,get_lambda,get_dynamo,get_apigw,get_elb]

# -------------------------------
# Stack Enumeration
# -------------------------------
def enumerate_stack(stack):
    log(f"Checking stack: {stack}")
    data = run_cli(["aws","cloudformation","describe-stack-resources","--stack-name",stack,"--output","json"])
    results={}
    for r in data.get("StackResources",[]):
        rtype,rid=r["ResourceType"],r["PhysicalResourceId"]
        if rtype=="AWS::CloudFormation::Stack":
            sub=enumerate_stack(rid)
            for k,v in sub.items(): results.setdefault(k,[]).extend(v)
        elif rtype=="AWS::S3::Bucket":
            loc = run_cli(["aws","s3api","get-bucket-location","--bucket",rid,"--output","json"])
            region = loc.get("LocationConstraint") or "us-east-1"
            url = f"https://{rid}.s3.{region}.amazonaws.com/"
            results.setdefault("S3 Buckets",[]).append({"Name":rid,"Region":region,"URL":url})
        elif rtype=="AWS::CloudFront::Distribution":
            dist=run_cli(["aws","cloudfront","get-distribution","--id",rid,"--output","json"])
            domain=dist["Distribution"]["DomainName"]
            results.setdefault("CloudFront Distributions",[]).append({"ID":rid,"Domain":domain})
        elif rtype=="AWS::RDS::DBInstance":
            rds=run_cli(["aws","rds","describe-db-instances","--db-instance-identifier",rid,"--output","json"])
            ep=rds["DBInstances"][0]["Endpoint"]["Address"]
            results.setdefault("RDS Databases",[]).append({"ID":rid,"Endpoint":ep})
        elif rtype=="AWS::EC2::Instance":
            ec2=run_cli(["aws","ec2","describe-instances","--instance-ids",rid,"--output","json"])
            inst=ec2["Reservations"][0]["Instances"][0]
            results.setdefault("EC2 Instances",[]).append({"ID":rid,"DNS":inst.get("PublicDnsName","N/A")})
    return results

# -------------------------------
# Prowler Integration
# -------------------------------
def run_prowler(services):
    log("Starting Prowler scan...")
    try:
        cmd=["prowler","aws","--services",",".join(services),"--output","json"]
        res=json.loads(subprocess.check_output(cmd,text=True))
        log(f"Prowler scan completed with {len(res.get('findings',[]))} findings")
        return res
    except Exception:
        log("Prowler scan failed or not installed")
        return None

def maybe_prowler(results):
    choice=input("Run Prowler scan? (y/n): ").lower()
    if choice!="y": return None
    print("1. All services\n2. Pick manually")
    opt=input("Choose: ")
    if opt=="1": services=[k.split()[0].lower() for k in results.keys()]
    else:
        for i,svc in enumerate(results.keys(),1): print(f"{i}. {svc}")
        picks=input("Select numbers: ").split(",")
        services=[list(results.keys())[int(p)-1].split()[0].lower() for p in picks]
    return run_prowler(services)

# -------------------------------
# Report Generator
# -------------------------------
def generate_report(results,prowler,fname):
    ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"Generating HTML report: {fname}")
    html=f"<html><head><title>{TOOL_NAME} Report</title></head><body>"
    html+=f"<h1>{TOOL_NAME} Report</h1><p>Generated: {ts}</p>"
    for svc,

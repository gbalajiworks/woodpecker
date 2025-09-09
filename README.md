Here’s a professional **GitHub repository description** for your Woodpecker project:

---

# 🪵 Woodpecker – AWS Inventory & Audit Tool

**Woodpecker** is a Python-based AWS enumeration and audit tool designed for cloud engineers, security teams, and DevOps professionals. It provides a clear, professional, and customizable way to list all AWS services, their resources, and URLs, and optionally perform security scans using Prowler.

### Features

* Enumerates AWS services and resources including S3, EC2, RDS, Lambda, DynamoDB, CloudFront, API Gateway, Load Balancers, and more.
* Supports **account-wide scans** or **CloudFormation stack-based scans**, including nested stacks.
* Generates a **professional HTML report** with clickable URLs for all discovered resources.
* Optional **Prowler integration** for AWS security audits.
* Real-time console logging to track progress.
* Easy to customize and extend for future AWS services.
* Lightweight and portable (<200 lines of code).

### Installation

```bash
git clone https://github.com/yourusername/woodpecker.git
cd woodpecker
pip install -r requirements.txt  # if additional dependencies are needed
```

### Usage

```bash
python woodpecker.py
```

* Choose **account scan** or **stack scan**
* Enter report filename
* Optionally initiate a Prowler scan

### Example Output

* HTML report with sections for each AWS service
* Resource URLs and endpoints included
* Prowler findings if enabled

### Requirements

* Python 3.8+
* AWS CLI configured with valid credentials
* Optional: [Prowler](https://github.com/toniblyx/prowler) installed for security scans

### License

MIT License



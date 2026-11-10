
# AWS Security Monitoring Lab

## Project Overview

This project demonstrates the implementation of an AWS security monitoring and alerting solution using Terraform.

The solution uses AWS CloudTrail to record account activity, Amazon CloudWatch to collect and analyse security events, and Amazon SNS to send email notifications when defined security events are detected.

The infrastructure is deployed using Terraform (Infrastructure as Code).

## Project Objectives

- Implement centralised AWS API activity monitoring.
- Capture management events using AWS CloudTrail.
- Store CloudTrail logs in Amazon S3.
- Forward CloudTrail events to Amazon CloudWatch Logs.
- Detect security-related events using CloudWatch Metric Filters.
- Configure CloudWatch Alarms for automated detection.
- Send email notifications using Amazon SNS.
- Manage AWS infrastructure using Terraform.

## AWS Services Used

| AWS Service | Purpose |
|---|---|
| AWS CloudTrail | Records AWS account activity and API events |
| Amazon S3 | Stores CloudTrail log files |
| Amazon CloudWatch Logs | Collects and stores CloudTrail events |
| Amazon CloudWatch | Creates metric filters and security alarms |
| Amazon SNS | Sends email notifications |
| AWS IAM | Controls service permissions and access |
| Terraform | Provisions and manages infrastructure |

## Deployment Region

`eu-north-1` (Europe – Stockholm)

---

## Architecture

The security monitoring solution follows this workflow:

1. AWS CloudTrail records management events across AWS regions.
2. CloudTrail delivers log files to an encrypted Amazon S3 bucket.
3. CloudTrail also forwards events to Amazon CloudWatch Logs.
4. CloudWatch Metric Filters inspect incoming logs for specific security events.
5. When a matching event is detected, a custom CloudWatch metric is generated.
6. CloudWatch Alarms evaluate these metrics over a five-minute period.
7. When an alarm threshold is reached, Amazon SNS sends an email notification.

### Architecture Components

| Component | Configuration |
|---|---|
| CloudTrail | Multi-region trail |
| Global Service Events | Enabled |
| Log File Validation | Enabled |
| S3 Public Access | Fully blocked |
| S3 Encryption | AES-256 server-side encryption |
| CloudWatch Log Retention | 7 days |
| Metric Namespace | SecurityLab |
| Alarm Evaluation Period | 5 minutes |
| Alarm Threshold | 1 matching event |
| Notification Method | SNS email |

---

## Security Detection Rules

The solution uses seven CloudWatch Metric Filters to identify potentially suspicious or security-sensitive activity.

| Detection Rule | Activity Monitored |
|---|---|
| Root Account Usage | Detects activity performed using the AWS root account |
| Security Group Changes | Detects creation, deletion, and modification of security groups |
| Network ACL Changes | Detects creation, deletion, and modification of network ACLs |
| IAM Policy Changes | Detects changes to IAM policies and policy attachments |
| Unauthorized API Calls | Detects API requests rejected due to authorization errors |
| Console Login Without MFA | Detects successful IAM user console logins without MFA |
| Failed Console Login | Detects unsuccessful console login attempts |

Each detection rule generates a custom CloudWatch metric. The corresponding alarm can notify the configured SNS email subscription when its threshold is reached.

---

## Testing and Validation

The monitoring solution was tested to verify that security events are detected and notifications are delivered.

Validation included:

- Verified that CloudTrail events were delivered to CloudWatch Logs.
- Confirmed that unauthorized API activity was detected by the relevant metric filter.
- Verified that the unauthorized API activity CloudWatch Alarm entered the ALARM state.
- Confirmed that the SNS email subscription was active.
- Published a test notification through SNS and confirmed email delivery.
- Verified end-to-end alert delivery from CloudWatch Alarms through SNS.

These tests demonstrate that the monitoring and notification workflow is operational.

---

## Deployment

### Prerequisites

Before deploying this project, you need:

- An AWS account.
- AWS CLI installed and configured.
- Terraform version 1.5 or later.
- Appropriate AWS IAM permissions.

### Configuration

The project uses Terraform variables for the AWS region and SNS alert email address.

The default deployment region is `eu-north-1`.

### Deployment Commands

Initialise Terraform:

```bash
terraform init

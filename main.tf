############################################
# Security monitoring lab
# CloudTrail -> S3 + CloudWatch Logs -> metric filters -> alarms -> SNS email
############################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "alert_email" {
  type        = string
  description = "Email address that receives alarm notifications"
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "lab-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  tags       = { Project = "security-monitoring-lab" }

  # Each entry becomes a metric filter + alarm
  filters = {
    root-usage = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

    security-group-changes = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"

    nacl-changes = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"

    iam-policy-changes = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"

    unauthorized-api-calls = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

    console-login-no-mfa = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"

    failed-console-login = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
  }
}

# ---------- S3 bucket for CloudTrail logs ----------
resource "aws_s3_bucket" "trail" {
  bucket        = "lab-cloudtrail-${local.account_id}-${var.region}"
  force_destroy = true # lets terraform destroy remove the bucket even with logs in it
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid = "AWSCloudTrailAclCheck"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid = "AWSCloudTrailWrite"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# ---------- CloudWatch Logs + role for CloudTrail ----------
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.trail_name}"
  retention_in_days = 7
  tags              = local.tags
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_to_cwl" {
  name               = "lab-cloudtrail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "trail_to_cwl" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  name   = "write-to-cloudwatch-logs"
  role   = aws_iam_role.trail_to_cwl.id
  policy = data.aws_iam_policy_document.trail_to_cwl.json
}

# ---------- The trail ----------
resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_to_cwl.arn
  tags                          = local.tags

  depends_on = [
    aws_s3_bucket_policy.trail,
    aws_iam_role_policy.trail_to_cwl,
  ]
}

# ---------- SNS email alerts ----------
resource "aws_sns_topic" "alerts" {
  name = "lab-security-alerts"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------- Metric filters + alarms ----------
resource "aws_cloudwatch_log_metric_filter" "f" {
  for_each       = local.filters
  name           = "lab-${each.key}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value

  metric_transformation {
    name      = each.key
    namespace = "SecurityLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "a" {
  for_each            = local.filters
  alarm_name          = "lab-${each.key}"
  alarm_description   = "Security lab alarm: ${each.key}"
  namespace           = "SecurityLab"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags

  depends_on = [aws_cloudwatch_log_metric_filter.f]
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

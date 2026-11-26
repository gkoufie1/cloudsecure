terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "CloudSecure", Environment = "lab", ManagedBy = "terraform" }
  }
}

variable "region" {
  type        = string
  description = "AWS region for the lab. Pass the same value to the scanner with --region."
  default     = "us-east-1"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for the origin host."
  default     = "t3.micro"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch retention for VPC flow logs and SSM session logs. PCI DSS 10.5.1 expects 365 for real environments."
  default     = 90
}

variable "manage_session_manager_preferences" {
  type        = bool
  description = "Manage the account/region-wide SSM-SessionManagerRunShell document to log sessions. Set false if it already exists and is managed elsewhere."
  default     = true
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only names[0] is used, for a single-AZ lab; the set growing does not move the subnets.
  state = "available"
}
data "aws_ssm_parameter" "ami" { name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" }

# ---------- Network ----------

resource "aws_vpc" "lab" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "cloudsecure-lab" }
}

# Strip all rules from the VPC's default security group (CIS / Security Hub EC2.2).
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "cloudsecure-default-deny" }
}

resource "aws_subnet" "edge" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.42.0.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "cloudsecure-edge" }
}

resource "aws_subnet" "isolated" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.42.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "cloudsecure-isolated" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "cloudsecure-igw" }
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "cloudsecure-edge" }
}

resource "aws_route_table_association" "edge" {
  subnet_id      = aws_subnet.edge.id
  route_table_id = aws_route_table.edge.id
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "cloudsecure-isolated" }
}

resource "aws_route_table_association" "isolated" {
  subnet_id      = aws_subnet.isolated.id
  route_table_id = aws_route_table.isolated.id
}

resource "aws_security_group" "origin" {
  name_prefix = "cloudsecure-origin-"
  description = "No inbound access; outbound TLS and tunnel"
  vpc_id      = aws_vpc.lab.id
  egress {
    description = "HTTPS to SSM, package repos and Cloudflare API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "egress" {
    for_each = toset(["tcp", "udp"])
    content {
      description = "Cloudflare Tunnel (${upper(egress.value)} 7844)"
      from_port   = 7844
      to_port     = 7844
      protocol    = egress.value
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  tags = { Name = "cloudsecure-origin" }
}

# ---------- Logging ----------

resource "aws_cloudwatch_log_group" "flow" {
  #checkov:skip=CKV_AWS_158:Lab uses the default CloudWatch encryption; customer-managed KMS is listed as future work.
  #checkov:skip=CKV_AWS_338:Retention is var.log_retention_days (90 by default, for cost); set 365 for PCI.
  name              = "/cloudsecure/vpc-flow-logs"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "flow" {
  name_prefix = "cloudsecure-flow-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = ["${aws_cloudwatch_log_group.flow.arn}", "${aws_cloudwatch_log_group.flow.arn}:*"]
    }]
  })
}

resource "aws_flow_log" "lab" {
  vpc_id                   = aws_vpc.lab.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow.arn
  max_aggregation_interval = 600
}

resource "aws_cloudwatch_log_group" "sessions" {
  #checkov:skip=CKV_AWS_158:Lab uses the default CloudWatch encryption; customer-managed KMS is listed as future work.
  #checkov:skip=CKV_AWS_338:Retention is var.log_retention_days (90 by default, for cost); set 365 for PCI.
  name              = "/cloudsecure/ssm-sessions"
  retention_in_days = var.log_retention_days
}

# Session Manager reads its logging preferences from this fixed document name (account + region wide).
resource "aws_ssm_document" "session_prefs" {
  #checkov:skip=CKV_AWS_112:Sessions already run over TLS; extra KMS session encryption needs a customer-managed key (future work).
  #checkov:skip=CKV_AWS_113:Session logs go to CloudWatch with default encryption; KMS log encryption is future work.
  count           = var.manage_session_manager_preferences ? 1 : 0
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"
  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Session Manager preferences: log sessions to CloudWatch"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = ""
      s3KeyPrefix                 = ""
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.sessions.name
      cloudWatchEncryptionEnabled = false
      cloudWatchStreamingEnabled  = true
      kmsKeyId                    = ""
      runAsEnabled                = false
      runAsDefaultUser            = ""
      idleSessionTimeout          = "20"
      shellProfile                = { windows = "", linux = "" }
    }
  })
}

# ---------- Instance ----------

resource "aws_iam_role" "origin" {
  name_prefix        = "cloudsecure-origin-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.origin.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Lets the SSM agent stream session transcripts to the session log group.
resource "aws_iam_role_policy" "session_logs" {
  role = aws_iam_role.origin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = ["${aws_cloudwatch_log_group.sessions.arn}", "${aws_cloudwatch_log_group.sessions.arn}:*"]
      },
      {
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "origin" {
  name_prefix = "cloudsecure-origin-"
  role        = aws_iam_role.origin.name
}

resource "aws_instance" "origin" {
  #checkov:skip=CKV_AWS_88:Public IPv4 is egress-only (no inbound rules) to avoid NAT gateway cost; see README design decisions.
  #checkov:skip=CKV_AWS_126:Detailed (1-minute) monitoring is a paid feature not needed for this lab.
  # insecure_value keeps the AMI ID visible in plans (value is always marked sensitive).
  ami                         = data.aws_ssm_parameter.ami.insecure_value
  instance_type               = var.instance_type
  ebs_optimized               = true
  subnet_id                   = aws_subnet.edge.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.origin.id]
  iam_instance_profile        = aws_iam_instance_profile.origin.name
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  root_block_device { encrypted = true }
  user_data                   = file("${path.module}/bootstrap.sh")
  user_data_replace_on_change = true
  tags                        = { Name = "cloudsecure-origin" }

  lifecycle {
    # A new AL2023 release must not silently replace the instance. Replace deliberately with:
    #   terraform apply -replace=aws_instance.origin
    ignore_changes = [ami]
  }
}

output "instance_id" { value = aws_instance.origin.id }
output "vpc_id" { value = aws_vpc.lab.id }
output "region" { value = var.region }
output "flow_log_group" { value = aws_cloudwatch_log_group.flow.name }
output "session_log_group" { value = aws_cloudwatch_log_group.sessions.name }

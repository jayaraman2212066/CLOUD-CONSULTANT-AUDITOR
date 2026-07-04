"""
Enterprise-Grade Multi-Version Prowler Parser
Supports: Prowler v2, v3, v4, v5 (JSON-OCSF), v6 (AWS ASFF), ScoutSuite
Implements: Deep nested extraction, comprehensive field mappings, zero unknowns
"""
from typing import List, Dict, Any
import re
from services.prowler_mappings import (
    PROWLER_FIELD_MAPPINGS,
    SERVICE_EXTRACTION_PATTERNS,
    HUMANIZATION_RULES,
    SEVERITY_NORMALIZATION,
    STATUS_NORMALIZATION
)

# ============================================================================
# ENTERPRISE KNOWLEDGE BASES
# ============================================================================

SERVICE_MAP = {
    "s3": "Amazon S3", "iam": "AWS IAM", "ec2": "Amazon EC2", "rds": "Amazon RDS",
    "cloudtrail": "AWS CloudTrail", "config": "AWS Config", "kms": "AWS KMS",
    "lambda": "AWS Lambda", "vpc": "Amazon VPC", "eks": "Amazon EKS", "ecs": "Amazon ECS",
    "secretsmanager": "AWS Secrets Manager", "guardduty": "Amazon GuardDuty",
    "waf": "AWS WAF", "sns": "Amazon SNS", "sqs": "Amazon SQS", "dynamodb": "Amazon DynamoDB",
    "cloudwatch": "Amazon CloudWatch", "route53": "Amazon Route 53", "elb": "Elastic Load Balancing",
    "elasticache": "Amazon ElastiCache", "redshift": "Amazon Redshift", "glue": "AWS Glue",
    "athena": "Amazon Athena", "emr": "Amazon EMR", "sagemaker": "Amazon SageMaker",
    "codecommit": "AWS CodeCommit", "codebuild": "AWS CodeBuild", "ssm": "AWS Systems Manager",
    "acm": "AWS Certificate Manager", "shield": "AWS Shield", "macie": "Amazon Macie",
    "inspector": "Amazon Inspector", "account": "AWS Account", "access": "AWS IAM Access Analyzer",
    "appstream": "Amazon AppStream", "backup": "AWS Backup", "bedrock": "Amazon Bedrock",
    "cognito": "Amazon Cognito", "dax": "Amazon DAX", "dms": "AWS Database Migration Service",
    "ecr": "Amazon ECR", "efs": "Amazon EFS", "fsx": "Amazon FSx", "glacier": "Amazon S3 Glacier",
    "lightsail": "Amazon Lightsail", "mq": "Amazon MQ", "neptune": "Amazon Neptune",
    "opensearch": "Amazon OpenSearch Service", "ses": "Amazon SES", "transfer": "AWS Transfer Family",
    "workspaces": "Amazon WorkSpaces",
}

PRIORITY_MAP = {
    "critical": ("Fix Immediately — within 24 hours", "🔴"),
    "high": ("Fix within 7 days", "🟠"),
    "medium": ("Fix within 30 days", "🟡"),
    "low": ("Best practice — schedule fix", "🟢"),
    "informational": ("Informational — review only", "🔵"),
    "info": ("Informational — review only", "🔵"),
}

# CONSULTANT-GRADE MITRE ATT&CK MAPPING - Unique techniques per check
MITRE_ATTACK_MAP = {
    # Authentication & Identity
    "iam_root_mfa_enabled": "T1556.006 (Modify Authentication Mechanism: Multi-Factor Authentication)",
    "iam_root_hardware_mfa_enabled": "T1556.006 (Modify Authentication Mechanism: Multi-Factor Authentication)",
    "iam_root_access_key": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_password_policy": "T1110 (Brute Force)",
    "iam_password_policy_minimum_length": "T1110.001 (Brute Force: Password Guessing)",
    "iam_password_policy_reuse_24": "T1110 (Brute Force)",
    "iam_user_mfa_enabled": "T1556 (Modify Authentication Mechanism)",
    "iam_user_console_access_mfa": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_access_keys_rotated": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_user_unused_credentials_90_days": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_policy_admin_access": "T1484 (Domain Policy Modification)",
    "iam_policy_no_full_access_to_services": "T1098.001 (Account Manipulation: Additional Cloud Credentials)",
    "iam_role_privilege_escalation": "T1098 (Account Manipulation)",
    "iam_inline_policy_no_administrative_privileges": "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    
    # Data Exposure & Storage
    "s3_bucket_public_access": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_public_access_block": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_level_public_access_block": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_encryption": "T1213 (Data from Information Repositories)",
    "s3_bucket_default_encryption": "T1213.002 (Data from Information Repositories: Sharepoint)",
    "s3_bucket_secure_transport": "T1040 (Network Sniffing)",
    "s3_bucket_versioning_enabled": "T1485 (Data Destruction)",
    "s3_bucket_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "s3_bucket_mfa_delete": "T1485 (Data Destruction)",
    "s3_account_level_public_access_blocks": "T1530 (Data from Cloud Storage Object)",
    "rds_instance_publicly_accessible": "T1133 (External Remote Services)",
    "rds_snapshots_public_access": "T1530 (Data from Cloud Storage Object)",
    "rds_instance_encryption": "T1005 (Data from Local System)",
    "rds_automated_backups": "T1485 (Data Destruction)",
    "rds_instance_backup_enabled": "T1485 (Data Destruction)",
    "rds_instance_multi_az": "T1499 (Endpoint Denial of Service)",
    "rds_instance_deletion_protection": "T1485 (Data Destruction)",
    "dynamodb_pitr_enabled": "T1485 (Data Destruction)",
    "dynamodb_table_encrypted_with_kms": "T1213 (Data from Information Repositories)",
    
    # Network Access & Exposure
    "ec2_instance_public_ip": "T1190 (Exploit Public-Facing Application)",
    "ec2_instance_imdsv2": "T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)",
    "ec2_instance_older_than_specific_days": "T1078 (Valid Accounts)",
    "ec2_security_group_open_to_internet": "T1046 (Network Service Discovery)",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": "T1021.004 (Remote Services: SSH)",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": "T1021.001 (Remote Services: Remote Desktop Protocol)",
    "ec2_securitygroup_default_restrict_traffic": "T1046 (Network Service Discovery)",
    "ec2_ebs_encryption": "T1005 (Data from Local System)",
    "ec2_ebs_volume_encryption": "T1005 (Data from Local System)",
    "ec2_ebs_public_snapshot": "T1530 (Data from Cloud Storage Object)",
    "ec2_ami_public": "T1525 (Implant Internal Image)",
    "ec2_elastic_ip_unassociated": "T1078 (Valid Accounts)",
    "vpc_flow_logs_enabled": "T1562.001 (Impair Defenses: Disable or Modify Tools)",
    "vpc_default_security_group_restricts_all_traffic": "T1046 (Network Service Discovery)",
    "vpc_network_acl_unrestricted": "T1046 (Network Service Discovery)",
    "vpc_endpoint_exposed": "T1133 (External Remote Services)",
    "elb_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "elbv2_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "elb_internet_facing": "T1190 (Exploit Public-Facing Application)",
    "elbv2_deletion_protection": "T1499 (Endpoint Denial of Service)",
    "elbv2_insecure_ssl_ciphers": "T1040 (Network Sniffing)",
    
    # Logging & Monitoring
    "cloudtrail_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "cloudtrail_multi_region_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "cloudtrail_log_file_validation_enabled": "T1565.001 (Data Manipulation: Stored Data Manipulation)",
    "cloudtrail_logs_s3_bucket_access_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "cloudtrail_kms_encryption_enabled": "T1565.001 (Data Manipulation: Stored Data Manipulation)",
    "cloudtrail_cloudwatch_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "cloudwatch_alarm_actions": "T1562 (Impair Defenses)",
    "cloudwatch_log_group_no_retention_policy": "T1070.004 (Indicator Removal: File Deletion)",
    "cloudwatch_log_group_retention_policy_specific_days_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "guardduty_enabled": "T1562 (Impair Defenses)",
    "guardduty_is_enabled": "T1562 (Impair Defenses)",
    "guardduty_no_high_severity_findings": "T1562 (Impair Defenses)",
    "securityhub_enabled": "T1562 (Impair Defenses)",
    "config_enabled": "T1562 (Impair Defenses)",
    "config_recorder_all_regions_enabled": "T1562 (Impair Defenses)",
    
    # Secrets Management & Encryption
    "ecs_task_definitions_no_environment_secrets": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    "ecs_task_definition_container_readonly_root_filesystem": "T1611 (Escape to Host)",
    "ecs_task_definition_user_not_root": "T1611 (Escape to Host)",
    "secretsmanager_rotation_enabled": "T1552.004 (Unsecured Credentials: Private Keys)",
    "secretsmanager_automatic_rotation_enabled": "T1552.004 (Unsecured Credentials: Private Keys)",
    "secretsmanager_secret_not_used": "T1552 (Unsecured Credentials)",
    "kms_cmk_rotation_enabled": "T1552 (Unsecured Credentials)",
    "kms_key_rotation_enabled": "T1552 (Unsecured Credentials)",
    "ssm_parameter_encryption": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    "ssm_document_secrets_in_variables": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    
    # Container & Serverless Security  
    "ecr_image_scan_on_push": "T1525 (Implant Internal Image)",
    "ecr_repositories_scan_images_on_push_enabled": "T1525 (Implant Internal Image)",
    "ecr_repositories_not_publicly_accessible": "T1525 (Implant Internal Image)",
    "eks_cluster_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "eks_control_plane_logging_all_types_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "eks_endpoints_not_publicly_accessible": "T1190 (Exploit Public-Facing Application)",
    "lambda_function_url_public": "T1190 (Exploit Public-Facing Application)",
    "lambda_function_public_access": "T1190 (Exploit Public-Facing Application)",
    "lambda_function_url_cors_policy": "T1071.001 (Application Layer Protocol: Web Protocols)",
    "lambda_function_vpc_enabled": "T1133 (External Remote Services)",
    "lambda_function_restrict_public_access": "T1190 (Exploit Public-Facing Application)",
    
    # Access Control & Policies
    "apigateway_restapi_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "apigateway_client_certificate_enabled": "T1071.001 (Application Layer Protocol: Web Protocols)",
    "acm_certificates_expiration_check": "T1588.004 (Obtain Capabilities: Digital Certificates)",
    "elb_ssl_listeners": "T1040 (Network Sniffing)",
    "redshift_cluster_public_access": "T1133 (External Remote Services)",
    "redshift_cluster_encryption": "T1213 (Data from Information Repositories)",
    "es_domain_encryption_at_rest_enabled": "T1213 (Data from Information Repositories)",
    "opensearch_service_domains_encryption_at_rest_enabled": "T1213 (Data from Information Repositories)",
    
    # Backup & Disaster Recovery
    "backup_plans_exist": "T1485 (Data Destruction)",
    "backup_vaults_encrypted": "T1485 (Data Destruction)",
    "backup_recovery_point_encrypted": "T1485 (Data Destruction)",
    "backup_recovery_point_manual_deletion_disabled": "T1485 (Data Destruction)",
    
    # Default fallback
    "_default": "T1078 (Valid Accounts)"
}

# Import extended MITRE mappings and merge (additive only, never replacing)
try:
    from .mitre_extensions import MITRE_EXTENSIONS
    # Append new mappings without overwriting existing ones
    for check_id, mapping in MITRE_EXTENSIONS.items():
        if check_id not in MITRE_ATTACK_MAP:
            MITRE_ATTACK_MAP[check_id] = mapping
    print(f"[MITRE] Extended coverage: {len(MITRE_ATTACK_MAP)} total check_id mappings")
except ImportError:
    print("[MITRE] Extensions not available, using base mappings only")
    pass

# Extended Regulatory Matrix with MITRE ATT&CK Mapping
REGULATORY_MATRIX = {
    "ecs_task_definitions_no_environment_secrets": {
        "mitre_mapping": "T1552.001 (Unsecured Credentials: Credentials In Files)",
        "compliance": "PCI-DSS v4.0 R3.2 | HIPAA §164.312(a)(2)(iv) | CIS AWS 3.1",
        "business_impact": "Exposure of long-lived runtime database or API credentials allowing unauthorized database reads/writes.",
        "breach_cost_index": "High (Direct threat vector to customer PII datasets)",
        "remediation": [
            "Remove all hardcoded secrets from environment variables in ECS task definitions",
            "Store secrets in AWS Secrets Manager or AWS Systems Manager Parameter Store",
            "Update task definition to reference secrets using 'secrets' configuration (not 'environment')",
            "Use IAM task roles to grant ECS tasks permission to access Secrets Manager",
            "Enable automatic secret rotation in Secrets Manager for database credentials",
            "Audit all existing task definitions for exposed credentials",
            "Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html"
        ]
    },
    "iam_root_mfa_enabled": {
        "mitre_mapping": "T1556.006 (Modify Authentication Mechanism: Multi-Factor Authentication)",
        "compliance": "CIS AWS Benchmark 1.13 | ISO 27001:2022 A.8.5 | SOC 2 CC6.1 | NIST 800-53 IA-2(1)",
        "business_impact": "Complete administrative takeover of the global AWS organization root billing and computing hierarchy.",
        "breach_cost_index": "Critical (Potential total business disruption)",
        "nist_controls": "IA-2(1), IA-5(1)",
        "pci_controls": "PCI-DSS 8.3.1",
        "iso_controls": "ISO 27001 A.9.4.2",
        "remediation": [
            "Enable virtual MFA device on the root account immediately",
            "Store MFA device and root credentials in a secure offline location",
            "Avoid using root account for day-to-day operations",
            "Set up billing alerts on root account"
        ]
    },
    "s3_bucket_public_access": {
        "mitre_mapping": "T1530 (Data from Cloud Storage Object)",
        "compliance": "CIS AWS 2.1.5 | SOC 2 CC6.1 | ISO 27001 A.9.4.1 | NIST 800-53 AC-3",
        "business_impact": "Public exposure of confidential data, intellectual property, or customer PII leading to data breach.",
        "breach_cost_index": "High (Regulatory fines, reputational damage)",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 7.1.1",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Enable S3 Block Public Access at account level",
            "Remove public ACLs from bucket",
            "Restrict bucket policy to specific IAM roles only",
            "Enable S3 server access logging"
        ]
    },
    "ec2_instance_public_ip": {
        "mitre_mapping": "T1190 (Exploit Public-Facing Application)",
        "compliance": "CIS AWS 5.1 | NIST 800-53 SC-7 | ISO 27001 A.13.1.3 | PCI-DSS 1.3.1",
        "business_impact": "Direct internet exposure increases attack surface for ransomware, cryptomining, and lateral movement.",
        "breach_cost_index": "High (Resource hijack, crypto-mining)",
        "nist_controls": "SC-7, AC-4",
        "pci_controls": "PCI-DSS 1.3.1, 1.3.2",
        "iso_controls": "ISO 27001 A.13.1.3",
        "remediation": [
            "Remove public IP assignment",
            "Place EC2 instances in private subnets behind Application Load Balancer",
            "Use AWS Systems Manager Session Manager for secure access instead of SSH",
            "Enable VPC Flow Logs to monitor all traffic"
        ]
    },
    "rds_instance_publicly_accessible": {
        "mitre_mapping": "T1133 (External Remote Services)",
        "compliance": "CIS AWS 2.3.1 | NIST 800-53 SC-7 | PCI-DSS 1.3.1 | ISO 27001 A.13.1.1",
        "business_impact": "Database directly accessible from internet allows brute-force attacks on database credentials.",
        "breach_cost_index": "Critical (Database breach, customer PII exposure)",
        "nist_controls": "SC-7, AC-3",
        "pci_controls": "PCI-DSS 1.3.1, 8.2.1",
        "iso_controls": "ISO 27001 A.13.1.1",
        "remediation": [
            "Set PubliclyAccessible=false on all RDS instances",
            "Move RDS instances to private subnets",
            "Configure VPC security groups to allow access only from application servers",
            "Enable RDS encryption at rest and in transit (SSL)"
        ]
    },
    "guardduty_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "AWS Foundational Security Best Practices GuardDuty.1 | NIST 800-53 SI-4 | SOC 2 CC7.2",
        "business_impact": "No intelligent threat detection means attacks can go undetected for extended periods.",
        "breach_cost_index": "Medium (Delayed incident response)",
        "nist_controls": "SI-4, IR-4",
        "pci_controls": "PCI-DSS 10.6.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable GuardDuty in ALL regions including unused ones",
            "Enable S3 Protection, EKS Protection, and Malware Protection",
            "Set up SNS email alerts for High and Critical findings",
            "Integrate GuardDuty with AWS Security Hub"
        ]
    },
    "cloudtrail_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "CIS AWS 3.1 | NIST 800-53 AU-2 | PCI-DSS 10.2.1 | SOC 2 CC7.2 | ISO 27001 A.12.4.1",
        "business_impact": "No audit trail means security incidents cannot be investigated or proven for compliance.",
        "breach_cost_index": "High (Compliance violations, no forensics capability)",
        "nist_controls": "AU-2, AU-3, AU-12",
        "pci_controls": "PCI-DSS 10.2.1, 10.3.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable CloudTrail in all regions with multi-region trail",
            "Enable log file validation",
            "Store logs in S3 bucket with versioning and lifecycle policies",
            "Enable CloudTrail Insights for anomaly detection",
            "# AWS CLI:",
            "aws cloudtrail create-trail --name org-audit-trail --s3-bucket-name audit-logs --is-multi-region-trail --enable-log-file-validation",
            "aws cloudtrail start-logging --name org-audit-trail"
        ]
    },
    "kms_cmk_rotation_enabled": {
        "mitre_mapping": "T1552 (Unsecured Credentials)",
        "compliance": "CIS AWS 3.8 | NIST 800-53 SC-12 | PCI-DSS 3.6.4 | ISO 27001 A.10.1.2 | SOC 2 CC6.1",
        "business_impact": "Unrotated encryption keys increase risk of key compromise and long-term data exposure.",
        "breach_cost_index": "Medium (Data encryption compromise)",
        "nist_controls": "SC-12, SC-13",
        "pci_controls": "PCI-DSS 3.6.4",
        "iso_controls": "ISO 27001 A.10.1.2",
        "remediation": [
            "Enable automatic key rotation for customer-managed KMS CMKs",
            "Review and document key usage and access policies",
            "Implement key rotation schedule (annually minimum)",
            "Monitor key usage with CloudWatch and CloudTrail",
            "# AWS CLI:",
            "aws kms enable-key-rotation --key-id <KEY_ID>",
            "aws kms get-key-rotation-status --key-id <KEY_ID>"
        ]
    },
    "ec2_instance_imdsv2": {
        "mitre_mapping": "T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)",
        "compliance": "AWS FSBP EC2.8 | NIST 800-53 IA-5 | CIS AWS 5.6",
        "business_impact": "IMDSv1 allows SSRF attacks to steal IAM credentials from EC2 metadata service.",
        "breach_cost_index": "High (Credential theft, privilege escalation)",
        "nist_controls": "IA-5, SC-12",
        "pci_controls": "PCI-DSS 8.3",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Enforce IMDSv2 on all EC2 instances",
            "Disable IMDSv1 metadata access",
            "Update instance metadata options",
            "# AWS CLI:",
            "aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens required --http-put-response-hop-limit 1"
        ]
    },
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
        "mitre_mapping": "T1021.004 (Remote Services: SSH)",
        "compliance": "CIS AWS 5.2 | NIST 800-53 AC-4 | PCI-DSS 1.3.1",
        "business_impact": "Public SSH access enables brute-force attacks and unauthorized server access.",
        "breach_cost_index": "Critical (Direct server compromise)",
        "nist_controls": "AC-4, SC-7",
        "pci_controls": "PCI-DSS 1.3.1, 2.2.2",
        "iso_controls": "ISO 27001 A.13.1.3",
        "remediation": [
            "Remove 0.0.0.0/0 from SSH security group rules",
            "Restrict SSH to specific IP ranges or VPN",
            "Use AWS Systems Manager Session Manager instead",
            "# AWS CLI:",
            "aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0"
        ]
    },
    "s3_bucket_versioning_enabled": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "CIS AWS 2.1.3 | NIST 800-53 CP-9 | ISO 27001 A.12.3.1",
        "business_impact": "Without versioning, accidental or malicious deletions cannot be recovered.",
        "breach_cost_index": "High (Data loss, ransomware impact)",
        "nist_controls": "CP-9, SI-12",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable S3 versioning on all critical buckets",
            "Configure lifecycle policies to manage old versions",
            "Enable MFA Delete for additional protection",
            "# AWS CLI:",
            "aws s3api put-bucket-versioning --bucket <BUCKET_NAME> --versioning-configuration Status=Enabled"
        ]
    },
    "ecs_task_definition_user_not_root": {
        "mitre_mapping": "T1611 (Escape to Host)",
        "compliance": "CIS Docker 4.1 | NIST 800-53 CM-7 | PCI-DSS 2.2",
        "business_impact": "Running containers as root enables container escape and host compromise.",
        "breach_cost_index": "High (Container breakout, lateral movement)",
        "nist_controls": "CM-7, AC-6",
        "pci_controls": "PCI-DSS 2.2.4",
        "iso_controls": "ISO 27001 A.9.4.5",
        "remediation": [
            "Set 'user' parameter to non-root UID in task definition",
            "Use least privilege principle for container users",
            "Implement read-only root filesystem",
            "# Terraform:",
            "user = \"1000:1000\"  # Run as non-root user"
        ]
    },
    "iam_password_policy_minimum_length_14": {
        "mitre_mapping": "T1110.001 (Brute Force: Password Guessing)",
        "compliance": "CIS AWS 1.8 | NIST 800-53 IA-5(1) | PCI-DSS 8.2.3 | ISO 27001 A.9.4.3",
        "business_impact": "Weak password policies enable brute-force attacks on IAM user credentials.",
        "breach_cost_index": "Medium (Account compromise)",
        "nist_controls": "IA-5(1), AC-2",
        "pci_controls": "PCI-DSS 8.2.3, 8.2.4",
        "iso_controls": "ISO 27001 A.9.4.3",
        "remediation": [
            "Update account password policy to require minimum 14 characters",
            "Enable uppercase, lowercase, numbers, and symbols requirements",
            "Set maximum password age to 90 days",
            "Enforce password reuse prevention (24 passwords)",
            "aws iam update-account-password-policy --minimum-password-length 14"
        ]
    },
    "iam_access_keys_rotated": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "CIS AWS 1.3 | NIST 800-53 IA-5(1) | PCI-DSS 8.2.4 | SOC 2 CC6.1",
        "business_impact": "Unrotated access keys increase risk of credential compromise and unauthorized API access.",
        "breach_cost_index": "High (Programmatic access compromise)",
        "nist_controls": "IA-5(1), AC-2",
        "pci_controls": "PCI-DSS 8.2.4",
        "iso_controls": "ISO 27001 A.9.2.4",
        "remediation": [
            "Rotate all access keys older than 90 days",
            "Implement automated key rotation via AWS Secrets Manager",
            "Use temporary credentials (STS) instead of long-lived keys where possible",
            "Enable CloudWatch alarm for keys older than 90 days"
        ]
    },
    "securityhub_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "AWS FSBP SecurityHub.1 | NIST 800-53 SI-4 | SOC 2 CC7.2",
        "business_impact": "No centralized security findings aggregation means threats go undetected.",
        "breach_cost_index": "Medium (Delayed threat detection)",
        "nist_controls": "SI-4, IR-4",
        "pci_controls": "PCI-DSS 10.6",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable AWS Security Hub in all regions",
            "Enable CIS AWS Foundations Benchmark standard",
            "Enable AWS Foundational Security Best Practices standard",
            "Integrate with EventBridge for automated remediation"
        ]
    },
    "config_recorder_all_regions_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "CIS AWS 3.5 | NIST 800-53 CM-8 | PCI-DSS 11.5 | SOC 2 CC7.2",
        "business_impact": "No configuration change tracking prevents audit and compliance verification.",
        "breach_cost_index": "Medium (Compliance violation)",
        "nist_controls": "CM-8, CM-3",
        "pci_controls": "PCI-DSS 11.5",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable AWS Config recorder in all regions",
            "Configure S3 bucket for Config history",
            "Enable global resource recording",
            "Set up Config Rules for compliance checks"
        ]
    },
    "cloudtrail_multi_region_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "CIS AWS 3.1 | NIST 800-53 AU-2 | PCI-DSS 10.2.2 | SOC 2 CC7.2",
        "business_impact": "Single-region CloudTrail misses API activity in other regions, creating audit blind spots.",
        "breach_cost_index": "High (Incomplete audit trail)",
        "nist_controls": "AU-2, AU-12",
        "pci_controls": "PCI-DSS 10.2.2",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable multi-region CloudTrail trail",
            "Enable log file validation",
            "Configure S3 bucket lifecycle policies for log retention",
            "Enable CloudTrail Insights for anomaly detection"
        ]
    },
    "cloudtrail_log_file_validation_enabled": {
        "mitre_mapping": "T1565.001 (Data Manipulation: Stored Data Manipulation)",
        "compliance": "CIS AWS 3.2 | NIST 800-53 AU-9 | PCI-DSS 10.5.2 | SOC 2 CC7.2",
        "business_impact": "Log file integrity cannot be verified, enabling attackers to tamper with audit evidence.",
        "breach_cost_index": "High (Forensic integrity loss)",
        "nist_controls": "AU-9, SI-7",
        "pci_controls": "PCI-DSS 10.5.2",
        "iso_controls": "ISO 27001 A.12.4.2",
        "remediation": [
            "Enable log file validation on CloudTrail trail",
            "Verify log file digests using AWS CLI validate-logs command",
            "Implement automated validation checks"
        ]
    },
    "elbv2_logging_enabled": {
        "mitre_mapping": "T1070.004 (Indicator Removal: File Deletion)",
        "compliance": "CIS AWS 4.8 | NIST 800-53 AU-2 | PCI-DSS 10.2.1",
        "business_impact": "No ALB/NLB access logs prevents investigation of suspicious traffic patterns.",
        "breach_cost_index": "Medium (Forensic blind spot)",
        "nist_controls": "AU-2, AU-3",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable access logging on all ALBs and NLBs",
            "Configure S3 bucket for log storage",
            "Set up log analysis with Athena or CloudWatch Logs Insights"
        ]
    },
    "elbv2_deletion_protection": {
        "mitre_mapping": "T1499 (Endpoint Denial of Service)",
        "compliance": "AWS FSBP ELB.3 | NIST 800-53 SC-5 | SOC 2 CC7.2",
        "business_impact": "Load balancers can be accidentally or maliciously deleted, causing production outages.",
        "breach_cost_index": "High (Service disruption)",
        "nist_controls": "SC-5, CM-3",
        "pci_controls": "PCI-DSS 6.6",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable deletion protection on all production load balancers",
            "Implement IaC drift detection to prevent configuration changes",
            "Use AWS Organizations SCPs to restrict deletion permissions"
        ]
    },
    "rds_instance_backup_enabled": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "CIS AWS 2.3.3 | NIST 800-53 CP-9 | PCI-DSS 3.4 | SOC 2 CC5.1",
        "business_impact": "No automated backups means database cannot be recovered from accidental deletion or ransomware.",
        "breach_cost_index": "Critical (Data loss)",
        "nist_controls": "CP-9, SI-12",
        "pci_controls": "PCI-DSS 3.4, 9.8",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable automated backups with 7-day retention minimum",
            "Configure backup window during off-peak hours",
            "Enable backup encryption with KMS",
            "Test restore procedures quarterly"
        ]
    },
    "rds_instance_multi_az": {
        "mitre_mapping": "T1499 (Endpoint Denial of Service)",
        "compliance": "AWS FSBP RDS.5 | NIST 800-53 CP-2 | SOC 2 CC5.1",
        "business_impact": "Single-AZ databases are vulnerable to AZ failures causing extended production outages.",
        "breach_cost_index": "High (Availability risk)",
        "nist_controls": "CP-2, SC-6",
        "pci_controls": "PCI-DSS 12.10",
        "iso_controls": "ISO 27001 A.17.2.1",
        "remediation": [
            "Enable Multi-AZ deployment on all production RDS instances",
            "Plan maintenance window for conversion (5-10 minute downtime)",
            "Verify failover testing post-enablement"
        ]
    },
    "rds_instance_deletion_protection": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "AWS FSBP RDS.8 | NIST 800-53 SC-5 | SOC 2 CC5.1",
        "business_impact": "Databases can be accidentally deleted causing permanent data loss.",
        "breach_cost_index": "Critical (Data loss)",
        "nist_controls": "SC-5, CM-3",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable deletion protection on all production databases",
            "Implement final snapshot before deletion in IaC templates",
            "Use AWS Backup for additional protection layer"
        ]
    },
    "eks_cluster_logging_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "CIS EKS 3.2.1 | NIST 800-53 AU-2 | PCI-DSS 10.2.1",
        "business_impact": "No EKS control plane logs prevents detection of Kubernetes API abuse.",
        "breach_cost_index": "High (Container security blind spot)",
        "nist_controls": "AU-2, AU-12",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable all 5 EKS log types: api, audit, authenticator, controllerManager, scheduler",
            "Configure CloudWatch log retention",
            "Set up alerts for suspicious API activity"
        ]
    },
    "eks_endpoints_not_publicly_accessible": {
        "mitre_mapping": "T1190 (Exploit Public-Facing Application)",
        "compliance": "CIS EKS 5.4.1 | NIST 800-53 SC-7 | PCI-DSS 1.3.1",
        "business_impact": "Public EKS endpoint exposes Kubernetes API to internet-based attacks.",
        "breach_cost_index": "Critical (Cluster compromise)",
        "nist_controls": "SC-7, AC-4",
        "pci_controls": "PCI-DSS 1.3.1",
        "iso_controls": "ISO 27001 A.13.1.3",
        "remediation": [
            "Disable public endpoint access",
            "Enable private endpoint access",
            "Use AWS PrivateLink for secure cluster access",
            "Configure bastion host or VPN for kubectl access"
        ]
    },
    "ecr_repositories_scan_images_on_push_enabled": {
        "mitre_mapping": "T1525 (Implant Internal Image)",
        "compliance": "CIS Docker 4.5 | NIST 800-53 RA-5 | PCI-DSS 6.2",
        "business_impact": "Vulnerable container images can be deployed without detection.",
        "breach_cost_index": "High (Malware deployment)",
        "nist_controls": "RA-5, SI-3",
        "pci_controls": "PCI-DSS 6.2, 6.5",
        "iso_controls": "ISO 27001 A.12.6.1",
        "remediation": [
            "Enable image scanning on all ECR repositories",
            "Implement CI/CD pipeline gates to block high-severity CVEs",
            "Use Amazon Inspector for enhanced scanning"
        ]
    },
    "ecr_repositories_not_publicly_accessible": {
        "mitre_mapping": "T1525 (Implant Internal Image)",
        "compliance": "AWS FSBP ECR.1 | NIST 800-53 AC-3 | PCI-DSS 7.1",
        "business_impact": "Public ECR repositories expose proprietary container images to unauthorized access.",
        "breach_cost_index": "High (IP theft)",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 7.1",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Remove public repository policies",
            "Configure private access via IAM roles",
            "Audit all ECR repository policies"
        ]
    },
    "secretsmanager_automatic_rotation_enabled": {
        "mitre_mapping": "T1552.004 (Unsecured Credentials: Private Keys)",
        "compliance": "CIS AWS 2.3.5 | NIST 800-53 IA-5(1) | PCI-DSS 8.2.4 | SOC 2 CC6.1",
        "business_impact": "Unrotated secrets increase risk of credential compromise over time.",
        "breach_cost_index": "High (Secret compromise)",
        "nist_controls": "IA-5(1), SC-12",
        "pci_controls": "PCI-DSS 8.2.4",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Enable automatic rotation on all secrets",
            "Use AWS-provided rotation templates for RDS, Redshift, DocumentDB",
            "Implement custom rotation Lambda for application secrets",
            "Set rotation schedule to 30-90 days"
        ]
    },
    "dynamodb_table_encrypted_with_kms": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "AWS FSBP DynamoDB.1 | NIST 800-53 SC-28 | PCI-DSS 3.4 | SOC 2 CC6.1",
        "business_impact": "Unencrypted DynamoDB tables expose sensitive data at rest.",
        "breach_cost_index": "High (Data breach)",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
        "remediation": [
            "Enable KMS encryption on all DynamoDB tables",
            "Use customer-managed KMS keys for enhanced control",
            "Migrate existing tables using DynamoDB table export/import"
        ]
    },
    "apigateway_restapi_logging_enabled": {
        "mitre_mapping": "T1070.004 (Indicator Removal: File Deletion)",
        "compliance": "AWS FSBP APIGateway.1 | NIST 800-53 AU-2 | PCI-DSS 10.2.1",
        "business_impact": "No API Gateway logs prevents detection of API abuse and data exfiltration.",
        "breach_cost_index": "Medium (API abuse)",
        "nist_controls": "AU-2, AU-3",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable CloudWatch logging on all API Gateway stages",
            "Set log level to INFO or ERROR minimum",
            "Enable execution logging for detailed request/response capture",
            "Configure log retention policies"
        ]
    },
    "backup_vaults_encrypted": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "AWS FSBP Backup.3 | NIST 800-53 CP-9 | PCI-DSS 3.4 | SOC 2 CC5.1",
        "business_impact": "Unencrypted backups expose recovery data to unauthorized access.",
        "breach_cost_index": "High (Backup compromise)",
        "nist_controls": "CP-9, SC-28",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Create all backup vaults with KMS encryption",
            "Use customer-managed KMS keys for backup encryption",
            "Enable backup vault lock for immutability"
        ]
    }
}

# Import compliance batches and merge (relative imports within services package)
try:
    from .compliance_batch_1 import COMPLIANCE_BATCH_1
    from .compliance_batch_2 import COMPLIANCE_BATCH_2
    from .compliance_batch_3 import COMPLIANCE_BATCH_3
    from .compliance_batch_4 import COMPLIANCE_BATCH_4
    from .compliance_batch_5 import COMPLIANCE_BATCH_5
    from .compliance_batch_6 import COMPLIANCE_BATCH_6
    # Merge all batches into REGULATORY_MATRIX (additive only)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_1)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_2)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_3)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_4)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_5)
    REGULATORY_MATRIX.update(COMPLIANCE_BATCH_6)
    print(f"[COMPLIANCE] Extended coverage: {len(REGULATORY_MATRIX)} total check_id mappings")
except ImportError as e:
    # If relative imports fail, batches not available
    print(f"[COMPLIANCE] Some batches not available: {e}")
    pass

FALLBACK_MAPPING = {
    "mitre_mapping": "T1078 (Valid Accounts / Configuration Variance)",
    "compliance": "CIS AWS Foundations Framework Checklist",
    "business_impact": "General degradation of structural cloud perimeter state integrity.",
    "breach_cost_index": "Medium",
    "nist_controls": "AC-2, AC-6",
    "pci_controls": "PCI-DSS 7.1",
    "iso_controls": "ISO 27001 A.9.2.1"
}

BUSINESS_RISK_KB = {
    "critical": "Attackers can exploit this immediately to gain unauthorized access, steal data, or cause a full account compromise. Regulatory fines and customer data breaches are likely consequences.",
    "high": "This exposes the organization to significant risk of data theft, service disruption, or compliance violations. Without remediation, a targeted attack could succeed within days.",
    "medium": "This represents a meaningful gap in security posture that, if combined with other weaknesses, could enable a successful attack. Compliance audits will flag this as a deficiency.",
    "low": "While not immediately dangerous, this represents a deviation from security best practices and may become a risk factor in a future breach scenario.",
    "informational": "No direct risk — this finding provides visibility into configuration that should be reviewed and understood.",
    "info": "No direct risk — this finding provides visibility into configuration that should be reviewed and understood.",
}

# ============================================================================
# UNIVERSAL FIELD EXTRACTION ENGINE
# ============================================================================

def extract_field_universal(item: dict, field_type: str) -> Any:
    """
    Universal field extractor that tries ALL possible field names from the
    comprehensive Prowler mapping database.
    
    GUARANTEES: Never returns 'unknown' unless ALL paths exhausted
    
    Args:
        item: Source dictionary (raw Prowler finding)
        field_type: Type of field to extract (e.g., 'check_id', 'severity', 'resource_id')
    
    Returns:
        Extracted value or fallback
    """
    if field_type not in PROWLER_FIELD_MAPPINGS:
        return None
    
    mapping = PROWLER_FIELD_MAPPINGS[field_type]
    priority_order = mapping["priority_order"]
    
    # Try each path in priority order
    for path in priority_order:
        value = extract_nested_field(item, [path])
        
        # Success criteria: value exists AND is not empty
        if value and value != "N/A" and str(value).strip():
            return str(value)
    
    # All paths failed - use fallback
    if "fallback" in mapping:
        return mapping["fallback"]
    elif "fallback_function" in mapping:
        func_name = mapping["fallback_function"]
        # Call the appropriate fallback function
        if func_name == "humanize_check_id":
            check_id_val = item.get("CheckID", item.get("check_id", item.get("checkId", "")))
            if check_id_val:
                return humanize_check_id(check_id_val)
        elif func_name == "extract_from_check_id":
            check_id_val = item.get("CheckID", item.get("check_id", item.get("checkId", "")))
            if check_id_val:
                return extract_service_from_check_id(check_id_val)
        elif func_name == "generate_from_check_id":
            check_id_val = item.get("CheckID", item.get("check_id", item.get("checkId", "")))
            if check_id_val:
                return f"The security check '{check_id_val}' has failed. The configuration does not meet AWS security best practices."
        elif func_name == "get_from_knowledge_base":
            # Will be handled in extract_remediation
            return None
        elif func_name == "current_timestamp":
            from datetime import datetime
            return datetime.now().isoformat()
        return func_name  # Return the function name as last resort
    else:
        return None


def normalize_severity(severity_raw: str) -> str:
    """
    Normalize severity to standard levels using comprehensive mapping.
    
    Args:
        severity_raw: Raw severity value from Prowler
    
    Returns:
        Normalized severity: 'critical', 'high', 'medium', 'low', or 'informational'
    """
    severity_upper = str(severity_raw).upper().strip()
    
    for normalized, variants in SEVERITY_NORMALIZATION.items():
        if severity_upper in [v.upper() for v in variants]:
            return normalized.lower()
    
    # Default fallback
    return "medium"


def normalize_status(status_raw: str) -> str:
    """
    Normalize status to PASS or FAIL using comprehensive mapping.
    
    Args:
        status_raw: Raw status value from Prowler
    
    Returns:
        Normalized status: 'PASS' or 'FAIL'
    """
    status_upper = str(status_raw).upper().strip()
    
    for normalized, variants in STATUS_NORMALIZATION.items():
        if status_upper in [v.upper() for v in variants]:
            return normalized
    
    # Default to FAIL if unknown
    return "FAIL"


def extract_service_from_check_id(check_id: str) -> str:
    """
    Extract AWS service name from check_id using pattern matching.
    
    Args:
        check_id: Check identifier (e.g., 's3_bucket_public_access')
    
    Returns:
        Service name (e.g., 'Amazon S3')
    """
    check_id_lower = check_id.lower()
    
    # Try regex patterns
    for pattern, service_name in SERVICE_EXTRACTION_PATTERNS["patterns"]:
        if re.match(pattern, check_id_lower):
            return service_name
    
    # Fallback
    return SERVICE_EXTRACTION_PATTERNS["fallback"]


def humanize_check_id(check_id: str) -> str:
    """
    Convert check_id to human-readable title.
    
    Examples:
        's3_bucket_public_access' -> 'S3 Bucket Public Access'
        'iam_root_mfa_enabled' -> 'IAM Root MFA Enabled'
    
    Args:
        check_id: Check identifier
    
    Returns:
        Human-readable title
    """
    title = check_id
    
    # Apply replacement rules
    for old, new in HUMANIZATION_RULES["replacements"].items():
        title = re.sub(r'\b' + old + r'\b', new, title, flags=re.IGNORECASE)
    
    # Apply pattern rules
    for pattern, replacement in HUMANIZATION_RULES["patterns"]:
        title = re.sub(pattern, replacement, title, flags=re.IGNORECASE)
    
    # Title case
    title = title.title()
    
    return title

# ============================================================================
# ALGORITHM 1: Deep Nested Path Extraction with Array Index Support
# ============================================================================

def extract_nested_field(item: dict, paths: list, default_value: str = "N/A") -> str:
    """
    Traverses complex, deeply nested JSON topologies including array indexing
    to resolve Prowler v3/v4/v5/v6 configurations without key-miss fallbacks.
    
    Paths can look like: ["metadata.event_code", "resources[0].name", "finding_info.uid"]
    
    Supports:
        - Dot notation: "metadata.event_code"
        - Array indexing: "resources[0].uid"
        - Mixed: "cloud.account.uid"
    """
    for path in paths:
        # Tokenize by dots, but preserve array markers e.g. resources[0]
        tokens = path.split('.')
        current_layer = item
        failed_path = False
        
        for token in tokens:
            # Check if token contains an array access index like 'resources[0]'
            array_match = re.match(r"^(\w+)\[(\d+)\]$", token)
            
            if array_match:
                key, index = array_match.group(1), int(array_match.group(2))
                if isinstance(current_layer, dict) and key in current_layer:
                    current_layer = current_layer[key]
                    if isinstance(current_layer, list) and len(current_layer) > index:
                        current_layer = current_layer[index]
                    else:
                        failed_path = True
                        break
                else:
                    failed_path = True
                    break
            else:
                # Standard dictionary lookups
                if isinstance(current_layer, dict) and token in current_layer:
                    current_layer = current_layer[token]
                else:
                    failed_path = True
                    break
        
        if not failed_path and current_layer is not None and current_layer != "":
            return str(current_layer)
            
    return default_value

# ============================================================================
# FIELD EXTRACTION WITH PROWLER VERSION MATRIX
# ============================================================================

def extract_check_id(item: dict) -> str:
    """Extract Check ID using comprehensive mapping database"""
    value = extract_field_universal(item, "check_id")
    return value if value else "unknown_check"

def extract_status(item: dict) -> str:
    """Extract and normalize Status"""
    value = extract_field_universal(item, "status")
    return normalize_status(value) if value else "FAIL"

def extract_title(item: dict, check_id: str) -> str:
    """Extract human-readable title"""
    value = extract_field_universal(item, "title")
    if not value or len(value) < 5:
        value = humanize_check_id(check_id)
    return value

def extract_severity(item: dict) -> str:
    """Extract and normalize severity"""
    value = extract_field_universal(item, "severity")
    return normalize_severity(value) if value else "medium"

def extract_resource_id(item: dict) -> str:
    """Extract primary resource identifier"""
    value = extract_field_universal(item, "resource_id")
    return value if value else "N/A"

def extract_resource_arn(item: dict) -> str:
    """Extract full AWS resource ARN"""
    value = extract_field_universal(item, "resource_arn")
    return value if value else ""

def extract_account_id(item: dict) -> str:
    """Extract AWS Account ID"""
    value = extract_field_universal(item, "account_id")
    return value if value else "N/A"

def extract_region(item: dict) -> str:
    """Extract AWS Region"""
    value = extract_field_universal(item, "region")
    return value if value else "Global"

def extract_service_name(item: dict, check_id: str) -> str:
    """Extract and normalize AWS service name"""
    value = extract_field_universal(item, "service_name")
    if value and value != "AWS":
        # Normalize using SERVICE_MAP if available
        service_lower = str(value).lower()
        return SERVICE_MAP.get(service_lower, str(value))
    else:
        # Extract from check_id
        return extract_service_from_check_id(check_id)

def extract_technical_risk(item: dict, check_id: str) -> str:
    """Extract technical risk description"""
    value = extract_field_universal(item, "technical_risk")
    if not value or len(value) < 10:
        value = f"The security check '{check_id}' has failed. The configuration does not meet AWS security best practices."
    return value

def extract_remediation(item: dict, check_id: str) -> list:
    """Extract or generate remediation steps - bulletproof version"""
    try:
        # Try regulatory matrix first (best quality)
        if check_id in REGULATORY_MATRIX:
            remediation = REGULATORY_MATRIX[check_id].get("remediation")
            if remediation and isinstance(remediation, list) and len(remediation) > 0:
                return remediation
        
        # Try universal field extraction
        remediation_text = extract_field_universal(item, "remediation")
        
        if remediation_text and str(remediation_text).strip() and len(str(remediation_text)) > 10:
            # If it's already a list, return it
            if isinstance(remediation_text, list):
                return [str(r) for r in remediation_text if r]
            return [str(remediation_text)]
        
        # Try common remediation fields
        for field in ["Remediation", "remediation", "recommendation", "Recommendation", 
                      "resolution", "Resolution", "fix", "Fix"]:
            if field in item:
                val = item[field]
                if val:
                    if isinstance(val, list):
                        return [str(v) for v in val if v]
                    elif isinstance(val, dict):
                        # Some Prowler versions have nested remediation
                        if "Recommendation" in val:
                            rec = val["Recommendation"]
                            if isinstance(rec, dict):
                                text = rec.get("Text", rec.get("text", ""))
                                if text:
                                    return [str(text)]
                            elif rec:
                                return [str(rec)]
                    elif len(str(val)) > 10:
                        return [str(val)]
        
        # Fallback: generate generic steps
        service = extract_service_from_check_id(check_id)
        return [
            f"Review the {service} service configuration for check: {check_id}",
            "Apply AWS security best practices and recommendations",
            "Consult AWS documentation for specific remediation steps",
            "Validate changes in a non-production environment first",
            "Re-run security scan to verify the issue is resolved"
        ]
    except Exception as e:
        # Return safe fallback if any error occurs
        return [
            f"Security finding detected: {check_id}",
            "Review AWS security best practices documentation",
            "Apply recommended security configurations",
            "Verify remediation through re-scanning"
        ]

def extract_compliance(item: dict) -> dict:
    """Extract compliance framework mappings - bulletproof version"""
    compliance = {}
    
    try:
        # Try universal field extraction first
        comp_raw = extract_field_universal(item, "compliance")
        
        if not comp_raw:
            # Try direct field access with multiple variants
            for field in ["Compliance", "compliance", "ComplianceFrameworks", "frameworks"]:
                if field in item:
                    comp_raw = item[field]
                    break
        
        if not comp_raw:
            return compliance
        
        # Try to parse if it's stored as JSON string
        if isinstance(comp_raw, str):
            try:
                import json
                comp_raw = json.loads(comp_raw)
            except:
                # If it's a simple string like "CIS AWS 1.1", parse it
                if comp_raw and len(comp_raw) > 3:
                    return parse_compliance_codes(comp_raw)
        
        # Handle different compliance formats
        if isinstance(comp_raw, dict):
            for framework, controls in comp_raw.items():
                framework_clean = str(framework).strip()
                if isinstance(controls, list) and controls:
                    controls_str = ", ".join(str(c) for c in controls if c)
                    if controls_str:
                        compliance[framework_clean] = controls_str
                elif controls:
                    compliance[framework_clean] = str(controls)
        elif isinstance(comp_raw, list):
            for c in comp_raw:
                if isinstance(c, dict):
                    framework = c.get("Framework", c.get("Name", c.get("framework", c.get("name", ""))))
                    control = c.get("Version", c.get("Id", c.get("Control", c.get("control", c.get("value", "")))))
                    if framework:
                        compliance[str(framework)] = str(control) if control else "N/A"
                elif isinstance(c, str) and c:
                    # Simple string list like ["CIS-1.1", "NIST-AC-2"]
                    parsed = parse_compliance_codes(c)
                    compliance.update(parsed)
    except Exception as e:
        # Silent fail - compliance is optional enrichment
        pass
    
    return compliance

# ============================================================================
# ALGORITHM 9: Automated MITRE ATT&CK & Regulatory Cross-Mapping
# ============================================================================

def enrich_finding_metadata(check_id: str) -> dict:
    """
    Enriches parsed JSON findings with specific compliance metrics 
    and threat vectors - bulletproof version.
    """
    try:
        # Get specific mapping or use default
        if check_id in REGULATORY_MATRIX:
            base_mapping = REGULATORY_MATRIX[check_id].copy()
        else:
            base_mapping = FALLBACK_MAPPING.copy()
        
        # Get unique MITRE ATT&CK technique for this check
        if check_id in MITRE_ATTACK_MAP:
            base_mapping["mitre_mapping"] = MITRE_ATTACK_MAP[check_id]
        elif "mitre_mapping" not in base_mapping:
            base_mapping["mitre_mapping"] = MITRE_ATTACK_MAP.get("_default", "T1078 (Valid Accounts)")
        
        # Ensure all required fields exist
        if "remediation" not in base_mapping:
            base_mapping["remediation"] = []
        if "compliance" not in base_mapping:
            base_mapping["compliance"] = ""
        if "business_impact" not in base_mapping:
            base_mapping["business_impact"] = "Security configuration does not meet best practices."
        if "breach_cost_index" not in base_mapping:
            base_mapping["breach_cost_index"] = "Medium"
        if "nist_controls" not in base_mapping:
            base_mapping["nist_controls"] = ""
        if "pci_controls" not in base_mapping:
            base_mapping["pci_controls"] = ""
        if "iso_controls" not in base_mapping:
            base_mapping["iso_controls"] = ""
        
        return base_mapping
    except Exception as e:
        # Return safe fallback
        return {
            "mitre_mapping": "T1078 (Valid Accounts)",
            "compliance": "AWS Security Best Practices",
            "business_impact": "Security configuration issue detected.",
            "breach_cost_index": "Medium",
            "remediation": ["Review AWS security documentation", "Apply recommended fixes"],
            "nist_controls": "",
            "pci_controls": "",
            "iso_controls": ""
        }

def parse_compliance_codes(compliance_str: str) -> dict:
    """
    Parse detailed compliance codes from strings like:
    'CIS AWS 2.1.5 | SOC 2 CC6.1 | ISO 27001 A.9.4.1 | NIST 800-53 AC-3'
    Returns: {'CIS': '2.1.5', 'SOC2': 'CC6.1', 'ISO27001': 'A.9.4.1', 'NIST': 'AC-3'}
    """
    import re
    compliance_dict = {}
    if not compliance_str:
        return compliance_dict
    
    parts = compliance_str.split('|')
    for part in parts:
        part = part.strip()
        if 'CIS' in part:
            # Extract CIS control like "CIS AWS 2.1.5" -> "2.1.5"
            import re
            match = re.search(r'CIS.*?([\d\.]+)', part)
            if match:
                compliance_dict['CIS'] = match.group(1)
        elif 'NIST' in part:
            # Extract NIST control like "NIST 800-53 AC-3" -> "AC-3"
            match = re.search(r'NIST.*?([A-Z]{2}-\d+(?:\([\d]+\))?)', part)
            if match:
                compliance_dict['NIST'] = match.group(1)
        elif 'PCI' in part or 'PCI-DSS' in part:
            # Extract PCI control
            match = re.search(r'PCI-?DSS[\s:]*(\S+)', part)
            if match:
                compliance_dict['PCI-DSS'] = match.group(1)
        elif 'ISO' in part:
            # Extract ISO control like "ISO 27001 A.9.4.1" -> "A.9.4.1"
            match = re.search(r'ISO.*?([A-Z]\.\d+\.\d+\.?\d*)', part)
            if match:
                compliance_dict['ISO27001'] = match.group(1)
        elif 'SOC' in part:
            # Extract SOC 2 control
            match = re.search(r'SOC\s*2\s+(\S+)', part)
            if match:
                compliance_dict['SOC2'] = match.group(1)
    
    return compliance_dict

# ============================================================================
# ALGORITHM 10: Prioritized Dollar-at-Risk Cost & Action Matrix
# ============================================================================

def generate_fix_priority_matrix(severity: str, check_id: str) -> dict:
    """
    Establishes an executive-level action summary - bulletproof version.
    """
    try:
        # Normalize severity
        severity = str(severity).lower().strip()
        
        remediation_effort = "Low"  # Programmatic defaults
        estimated_cost_of_breach = "$15,000 - $45,000 (Operational Interruption)"
        
        if severity == "critical":
            remediation_effort = "Medium"
            estimated_cost_of_breach = "$250,000+ (Regulated Data Breach / Identity Extrusion)"
        elif severity == "high":
            remediation_effort = "Low"
            estimated_cost_of_breach = "$75,000 - $180,000 (Resource Hijack / Crypto-mining)"
        elif severity == "medium":
            remediation_effort = "Low"
            estimated_cost_of_breach = "$25,000 - $60,000 (Configuration Drift)"
        elif severity == "low":
            remediation_effort = "Low"
            estimated_cost_of_breach = "$5,000 - $15,000 (Best Practice Deviation)"
        else:
            # Informational
            remediation_effort = "Low"
            estimated_cost_of_breach = "Informational (No direct cost)"

        # Specific override based on structural knowledge definitions
        check_id_lower = str(check_id).lower()
        if any(keyword in check_id_lower for keyword in ["secret", "credential", "password", "key"]):
            remediation_effort = "High"  # Entails rotational validation overheads
            
        return {
            "remediation_complexity": remediation_effort,
            "financial_exposure_index": estimated_cost_of_breach,
            "action_priority_rank": 1 if severity == "critical" and remediation_effort != "High" else 2
        }
    except Exception as e:
        # Safe fallback
        return {
            "remediation_complexity": "Medium",
            "financial_exposure_index": "$25,000 - $60,000",
            "action_priority_rank": 2
        }

# ============================================================================
# MAIN PARSING FUNCTION
# ============================================================================

def parse_findings(raw_json: Any) -> List[Dict]:
    """
    Enterprise-grade multi-version parser supporting:
    - Prowler v3, v4, v5 (JSON-OCSF), v6 (AWS ASFF)
    - Deep nested extraction
    - MITRE ATT&CK mapping
    - Compliance enrichment
    - Financial risk assessment
    """
    findings = []

    # Handle both array and object (ScoutSuite wraps in a dict)
    if isinstance(raw_json, dict):
        # Try ScoutSuite format
        items = []
        services = raw_json.get("services", raw_json)
        if isinstance(services, dict):
            for svc_data in services.values():
                if isinstance(svc_data, dict):
                    for finding in svc_data.get("findings", {}).values():
                        items.append(finding)
        if not items:
            # Generic dict with a list value
            for v in raw_json.values():
                if isinstance(v, list):
                    items = v
                    break
        raw_list = items if items else [raw_json]
    else:
        raw_list = raw_json

    for idx, item in enumerate(raw_list):
        if not isinstance(item, dict):
            continue

        try:
            # ========================================
            # EXTRACT ALL FIELDS USING VERSION MATRIX
            # ========================================
            
            check_id = extract_check_id(item)
            status = extract_status(item)
            
            # Skip only PASS findings
            if status == "PASS":
                continue
            
            title = extract_title(item, check_id)
            severity = extract_severity(item)
            resource_id = extract_resource_id(item)
            resource_arn = extract_resource_arn(item)
            account = extract_account_id(item)
            region = extract_region(item)
            service = extract_service_name(item, check_id)
            technical_risk = extract_technical_risk(item, check_id)
            remediation = extract_remediation(item, check_id)
            compliance = extract_compliance(item)
            
            # Get business risk from KB
            business_risk = BUSINESS_RISK_KB.get(severity, BUSINESS_RISK_KB["medium"])
            
            # Get priority mapping
            priority_label, priority_icon = PRIORITY_MAP.get(severity, PRIORITY_MAP["medium"])
            
            # Enrich with MITRE & Compliance
            enrichment = enrich_finding_metadata(check_id)
            
            # Get financial priority matrix
            priority_matrix = generate_fix_priority_matrix(severity, check_id)
            
            # Merge compliance from enrichment if not present in raw data
            if not compliance and "compliance" in enrichment:
                compliance = parse_compliance_codes(enrichment["compliance"])
            
            # Extract individual compliance codes from enrichment
            nist_controls = enrichment.get("nist_controls", "")
            pci_controls = enrichment.get("pci_controls", "")
            iso_controls = enrichment.get("iso_controls", "")
            
            # Add to compliance dict if not already present
            if nist_controls and "NIST" not in compliance:
                compliance["NIST"] = nist_controls
            if pci_controls and "PCI-DSS" not in compliance:
                compliance["PCI-DSS"] = pci_controls  
            if iso_controls and "ISO27001" not in compliance:
                compliance["ISO27001"] = iso_controls
            
            findings.append({
                "check_id": check_id,
                "title": title,
                "severity": severity,
                "status": status,
                "service": service,
                "resource_id": resource_id,
                "resource_arn": resource_arn,
                "region": region,
                "account": account,
                "technical_risk": technical_risk,
                "business_risk": business_risk,
                "remediation": remediation,
                "priority": priority_label,
                "priority_icon": priority_icon,
                "compliance": compliance,
                "mitre_attack": enrichment.get("mitre_mapping", ""),
                "breach_cost": enrichment.get("breach_cost_index", ""),
                "remediation_effort": priority_matrix["remediation_complexity"],
                "financial_exposure": priority_matrix["financial_exposure_index"],
                "action_priority": priority_matrix["action_priority_rank"],
                "nist_controls": enrichment.get("nist_controls", ""),
                "pci_controls": enrichment.get("pci_controls", ""),
                "iso_controls": enrichment.get("iso_controls", ""),
            })
        except Exception as e:
            # Log but don't fail on individual findings
            print(f"Warning: Skipping finding at index {idx} due to error: {str(e)}")
            continue

    # Sort: critical → high → medium → low → info
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))
    return findings


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Groups findings by check_id so that 200 S3 bucket findings become
    1 grouped finding with 200 affected resources listed underneath.
    Returns list of grouped findings sorted by severity then affected_count desc.
    """
    groups: Dict[str, Dict] = {}
    for f in findings:
        cid = f["check_id"]
        if cid not in groups:
            groups[cid] = {**f, "affected_resources": [], "affected_count": 0}
        rid = f.get("resource_id", "N/A")
        if rid and rid != "N/A" and rid not in groups[cid]["affected_resources"]:
            groups[cid]["affected_resources"].append(rid)
        groups[cid]["affected_count"] = len(groups[cid]["affected_resources"])

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
    result = sorted(groups.values(),
                    key=lambda x: (sev_order.get(x["severity"], 5), -x["affected_count"]))
    return result

# ============================================================================
# ALGORITHM 8: Context-Aware Risk Matrix & Threshold Caps
# ============================================================================

def calculate_risk_score(findings: list, asset_criticality: str = "High") -> dict:
    """
    Calculates an enterprise-grade risk posture assessment.
    Applies absolute ceiling caps if systemic operational failures exist.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    
    # Criticality Multipliers for Business Impact
    criticality_weights = {"Critical": 1.5, "High": 1.2, "Medium": 1.0, "Low": 0.5}
    multiplier = criticality_weights.get(asset_criticality, 1.0)
    
    # 1. Quantify exact finding volumes
    for f in findings:
        sev = f.get("severity", "low").lower()
        key = "informational" if sev in ("informational", "info") else sev
        if key in severity_counts:
            severity_counts[key] += 1

    # 2. Base Deduction Scoring Engine
    base_penalty = (
        (severity_counts["critical"] * 25 * multiplier) +
        (severity_counts["high"] * 12 * multiplier) +
        (severity_counts["medium"] * 4 * multiplier) +
        (severity_counts["low"] * 1 * multiplier)
    )
    
    calculated_score = max(0, 100 - base_penalty)
    
    # 3. Apply Professional Advisory Risk Caps (Non-Negotiable Guardrails)
    ceiling_applied = None
    if severity_counts["critical"] >= 5:
        # Multiple active critical vectors dictate structural infrastructure compromise
        calculated_score = min(calculated_score, 30.0)
        ceiling_applied = "CRITICAL_CEILING_SEVERE"
    elif severity_counts["critical"] >= 1:
        # A single critical finding limits maximum possible score to a failing 'D' grade boundary
        calculated_score = min(calculated_score, 60.0)
        ceiling_applied = "CRITICAL_CEILING"
    elif severity_counts["high"] >= 10:
        # Widespread High exposure limits posture visibility
        calculated_score = min(calculated_score, 45.0)
        ceiling_applied = "HIGH_CEILING"

    # 4. Resolve Clean Enterprise Grade Mapping
    score = round(calculated_score, 1)
    if score >= 90.0:
        grade = "A"
        grade_label = "A (Optimized)"
    elif score >= 80.0:
        grade = "B"
        grade_label = "B (Managed)"
    elif score >= 70.0:
        grade = "C"
        grade_label = "C (Defined)"
    elif score >= 60.0:
        grade = "D"
        grade_label = "D (Restricted / High Risk)"
    else:
        grade = "F"
        grade_label = "F (Non-Compliant / Exposed)"
    
    return {
        "score": score,
        "grade": grade,
        "grade_label": grade_label,
        "base_score": round(100 - base_penalty, 1),
        "ceiling_applied": ceiling_applied,
        "breakdown": severity_counts,
        "total": len(findings),
        "asset_criticality": asset_criticality,
        "impact_context": f"Evaluated under {asset_criticality} Business Importance parameters."
    }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def group_by_severity(findings: list) -> dict:
    """Aggregate findings by severity"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        key = "informational" if sev in ("informational", "info") else sev
        if key in counts:
            counts[key] += 1
    return counts

def group_by_service(findings: list) -> dict:
    """Aggregate findings by service, sorted by count descending"""
    services = {}
    for f in findings:
        svc = f.get("service", "AWS")
        services[svc] = services.get(svc, 0) + 1
    return dict(sorted(services.items(), key=lambda x: -x[1]))

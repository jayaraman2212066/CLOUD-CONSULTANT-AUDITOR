"""
COMPLIANCE_BATCH_5: Additional Compliance Framework Mappings
Extends REGULATORY_MATRIX with mappings for newer Prowler checks
Covers CIS, NIST 800-53, PCI-DSS, ISO 27001, SOC 2
"""

COMPLIANCE_BATCH_5 = {
    # IAM Extended Compliance
    "iam_no_root_access_key": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "CIS AWS 1.4 | NIST 800-53 IA-2 | PCI-DSS 8.1.1 | ISO 27001 A.9.2.1",
        "business_impact": "Root access keys provide unrestricted access and cannot have MFA enforced, creating permanent backdoor risk.",
        "breach_cost_index": "Critical (Complete account takeover)",
        "nist_controls": "IA-2, AC-2",
        "pci_controls": "PCI-DSS 8.1.1, 8.2.3",
        "iso_controls": "ISO 27001 A.9.2.1",
        "remediation": [
            "Delete all root account access keys immediately",
            "aws iam delete-access-key --access-key-id <ROOT_KEY_ID> --user-name root",
            "Use IAM users or roles with MFA for administrative tasks",
            "Enable CloudWatch alarm for root account usage"
        ]
    },
    
    "iam_rotate_access_key_90_days": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "CIS AWS 1.3 | NIST 800-53 IA-5(1) | PCI-DSS 8.2.4 | SOC 2 CC6.1",
        "business_impact": "Stale access keys increase credential compromise window.",
        "breach_cost_index": "High",
        "nist_controls": "IA-5(1), AC-2(7)",
        "pci_controls": "PCI-DSS 8.2.4",
        "iso_controls": "ISO 27001 A.9.2.4",
        "remediation": [
            "Rotate all access keys older than 90 days",
            "Implement automated key rotation using AWS Secrets Manager",
            "Enable CloudWatch alarm for keys older than 90 days"
        ]
    },
    
    "iam_support_role_exists": {
        "mitre_mapping": "T1098 (Account Manipulation)",
        "compliance": "CIS AWS 1.20 | NIST 800-53 IR-7 | SOC 2 CC7.4",
        "business_impact": "No AWS Support access during incidents delays resolution.",
        "breach_cost_index": "Medium",
        "nist_controls": "IR-7, CP-2",
        "pci_controls": "PCI-DSS 12.10.1",
        "iso_controls": "ISO 27001 A.16.1.5",
        "remediation": [
            "Create IAM role with AWSSupportAccess policy",
            "Assign role to appropriate IAM users or groups",
            "Test support case creation access"
        ]
    },
    
    # S3 Extended Compliance
    "s3_bucket_object_lock_enabled": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "CIS AWS 2.1.3 | NIST 800-53 CP-9 | PCI-DSS 3.4 | SOC 2 CC5.1",
        "business_impact": "Without object lock, data can be deleted even with versioning enabled.",
        "breach_cost_index": "High (Ransomware protection)",
        "nist_controls": "CP-9, SI-12",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable S3 Object Lock on critical buckets",
            "Configure retention mode (Governance or Compliance)",
            "Set retention period based on compliance requirements",
            "Test restore procedures"
        ]
    },
    
    "s3_bucket_acl_prohibited": {
        "mitre_mapping": "T1530 (Data from Cloud Storage Object)",
        "compliance": "CIS AWS 2.1.5 | NIST 800-53 AC-3 | PCI-DSS 7.1",
        "business_impact": "Bucket ACLs bypass bucket policies, creating shadow access paths.",
        "breach_cost_index": "High",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 7.1.1, 7.2.1",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Enable S3 Block Public Access for bucket ACLs",
            "Use bucket policies for access control instead of ACLs",
            "Audit and remove existing public ACLs"
        ]
    },
    
    # EC2 Extended Compliance
    "ec2_instance_managed_by_ssm": {
        "mitre_mapping": "T1078 (Valid Accounts)",
        "compliance": "NIST 800-53 CM-8 | SOC 2 CC8.1",
        "business_impact": "Instances not managed by SSM lack centralized patching and configuration management.",
        "breach_cost_index": "Medium",
        "nist_controls": "CM-8, CM-7",
        "pci_controls": "PCI-DSS 2.4",
        "iso_controls": "ISO 27001 A.12.5.1",
        "remediation": [
            "Install SSM agent on all EC2 instances",
            "Attach IAM role with AmazonSSMManagedInstanceCore policy",
            "Register instances in Systems Manager",
            "Enable Session Manager for secure access"
        ]
    },
    
    "ec2_instance_termination_protection": {
        "mitre_mapping": "T1499 (Endpoint Denial of Service)",
        "compliance": "NIST 800-53 SC-5 | SOC 2 CC7.2",
        "business_impact": "Production instances can be accidentally terminated causing outages.",
        "breach_cost_index": "High",
        "nist_controls": "SC-5, CM-3",
        "pci_controls": "PCI-DSS 6.6",
        "iso_controls": "ISO 27001 A.12.3.1",
        "remediation": [
            "Enable termination protection on production instances",
            "aws ec2 modify-instance-attribute --instance-id <ID> --disable-api-termination",
            "Use IaC drift detection to prevent unauthorized changes"
        ]
    },
    
    # RDS Extended Compliance
    "rds_instance_iam_authentication_enabled": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "NIST 800-53 IA-2(1) | PCI-DSS 8.3.1 | SOC 2 CC6.1",
        "business_impact": "Database authentication via IAM eliminates password management risks.",
        "breach_cost_index": "Medium",
        "nist_controls": "IA-2(1), IA-5(1)",
        "pci_controls": "PCI-DSS 8.3.1",
        "iso_controls": "ISO 27001 A.9.4.2",
        "remediation": [
            "Enable IAM database authentication on RDS instance",
            "aws rds modify-db-instance --db-instance-identifier <ID> --enable-iam-database-authentication --apply-immediately",
            "Create database users that use IAM authentication",
            "Update application to use IAM tokens for database connections"
        ]
    },
    
    "rds_instance_enhanced_monitoring_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "NIST 800-53 SI-4 | SOC 2 CC7.2",
        "business_impact": "Enhanced monitoring provides OS-level metrics for performance troubleshooting.",
        "breach_cost_index": "Low",
        "nist_controls": "SI-4, AU-6",
        "pci_controls": "PCI-DSS 10.6.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable enhanced monitoring on RDS instance",
            "Set monitoring interval (1, 5, 10, 15, 30, or 60 seconds)",
            "Grant RDS permission to publish metrics to CloudWatch"
        ]
    },
    
    # CloudWatch Extended Compliance
    "cloudwatch_log_metric_filter_authentication_failures": {
        "mitre_mapping": "T1110 (Brute Force)",
        "compliance": "CIS AWS 4.6 | NIST 800-53 AU-6 | PCI-DSS 10.2.4",
        "business_impact": "Undetected authentication failures indicate potential brute-force attacks.",
        "breach_cost_index": "High",
        "nist_controls": "AU-6, SI-4",
        "pci_controls": "PCI-DSS 10.2.4, 10.2.5",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Create CloudWatch log metric filter for authentication failures",
            "Configure alarm for threshold breaches",
            "Integrate with SNS for notifications",
            "Filter pattern: { ($.errorCode = '*UnauthorizedOperation') || ($.errorCode = 'AccessDenied*') }"
        ]
    },
    
    "cloudwatch_log_metric_filter_root_usage": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "CIS AWS 4.3 | NIST 800-53 AU-6 | PCI-DSS 10.2.5",
        "business_impact": "Root account usage should trigger immediate alerts.",
        "breach_cost_index": "Critical",
        "nist_controls": "AU-6, AC-2",
        "pci_controls": "PCI-DSS 10.2.5",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Create log metric filter for root account usage",
            "Filter pattern: { $.userIdentity.type = 'Root' && $.userIdentity.invokedBy NOT EXISTS && $.eventType != 'AwsServiceEvent' }",
            "Configure high-severity alarm",
            "Set up SNS notification to security team"
        ]
    },
    
    # Lambda Extended Compliance
    "lambda_function_using_supported_runtimes": {
        "mitre_mapping": "T1203 (Exploitation for Client Execution)",
        "compliance": "NIST 800-53 SI-2 | PCI-DSS 6.2 | SOC 2 CC8.1",
        "business_impact": "Deprecated runtimes lack security patches, creating known vulnerabilities.",
        "breach_cost_index": "High",
        "nist_controls": "SI-2, RA-5",
        "pci_controls": "PCI-DSS 6.2",
        "iso_controls": "ISO 27001 A.12.6.1",
        "remediation": [
            "Identify functions using deprecated runtimes",
            "Upgrade to latest supported runtime version",
            "Test function compatibility after upgrade",
            "Enable Lambda runtime deprecation notifications"
        ]
    },
    
    "lambda_function_no_secrets_in_code": {
        "mitre_mapping": "T1552.001 (Unsecured Credentials: Credentials In Files)",
        "compliance": "CIS AWS 2.3.1 | NIST 800-53 IA-5(7) | PCI-DSS 8.2.1",
        "business_impact": "Hardcoded secrets in Lambda code expose credentials in version control and deployment artifacts.",
        "breach_cost_index": "Critical",
        "nist_controls": "IA-5(7), SC-12",
        "pci_controls": "PCI-DSS 8.2.1",
        "iso_controls": "ISO 27001 A.9.4.3",
        "remediation": [
            "Remove all hardcoded secrets from Lambda function code",
            "Store secrets in AWS Secrets Manager or Parameter Store",
            "Grant Lambda function IAM permission to access secrets",
            "Update code to retrieve secrets at runtime",
            "Rotate all exposed secrets immediately"
        ]
    },
    
    # ELB Extended Compliance
    "elbv2_waf_acl_attached": {
        "mitre_mapping": "T1190 (Exploit Public-Facing Application)",
        "compliance": "NIST 800-53 SC-7 | PCI-DSS 6.6 | SOC 2 CC6.6",
        "business_impact": "Load balancers without WAF are vulnerable to OWASP Top 10 attacks.",
        "breach_cost_index": "High",
        "nist_controls": "SC-7, SI-3",
        "pci_controls": "PCI-DSS 6.6",
        "iso_controls": "ISO 27001 A.13.1.3",
        "remediation": [
            "Create AWS WAF web ACL with appropriate rules",
            "Attach web ACL to Application Load Balancer",
            "Enable AWS WAF logging for analysis",
            "Configure rate limiting and geo-blocking as needed"
        ]
    },
    
    # SNS Extended Compliance
    "sns_topics_not_publicly_accessible": {
        "mitre_mapping": "T1071.001 (Application Layer Protocol: Web Protocols)",
        "compliance": "CIS AWS 2.3.1 | NIST 800-53 AC-3 | PCI-DSS 7.1",
        "business_impact": "Public SNS topics allow unauthorized message publication or subscription.",
        "breach_cost_index": "Medium",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 7.1.1",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Review SNS topic policies for wildcard principals",
            "Remove public access from topic policies",
            "Restrict access to specific AWS accounts or IAM roles",
            "Enable SNS encryption for sensitive topics"
        ]
    },
    
    # SQS Extended Compliance
    "sqs_queues_not_publicly_accessible": {
        "mitre_mapping": "T1071.001 (Application Layer Protocol: Web Protocols)",
        "compliance": "CIS AWS 2.3.1 | NIST 800-53 AC-3 | PCI-DSS 7.1",
        "business_impact": "Public SQS queues allow message injection or unauthorized consumption.",
        "breach_cost_index": "Medium",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 7.1.1",
        "iso_controls": "ISO 27001 A.9.4.1",
        "remediation": [
            "Review SQS queue policies for wildcard principals",
            "Remove public access from queue policies",
            "Use IAM policies for access control",
            "Enable SQS encryption with KMS"
        ]
    },
    
    # Redshift Extended Compliance
    "redshift_cluster_audit_logging": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "CIS AWS 2.3.1 | NIST 800-53 AU-2 | PCI-DSS 10.2.1",
        "business_impact": "Redshift audit logs track database connections and query execution for security analysis.",
        "breach_cost_index": "Medium",
        "nist_controls": "AU-2, AU-3",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable audit logging on Redshift cluster",
            "Configure S3 bucket for log storage",
            "Set log retention period per compliance requirements",
            "Enable user activity logging"
        ]
    },
    
    # ECS Extended Compliance
    "ecs_task_definition_no_privileged_containers": {
        "mitre_mapping": "T1611 (Escape to Host)",
        "compliance": "CIS Docker 5.1 | NIST 800-53 CM-7 | PCI-DSS 2.2",
        "business_impact": "Privileged containers have full access to host resources, enabling container escape.",
        "breach_cost_index": "Critical",
        "nist_controls": "CM-7, AC-6",
        "pci_controls": "PCI-DSS 2.2.4",
        "iso_controls": "ISO 27001 A.9.4.5",
        "remediation": [
            "Remove 'privileged: true' from all container definitions",
            "Grant specific capabilities only if absolutely required",
            "Use read-only root filesystem where possible",
            "Implement AppArmor or SELinux profiles"
        ]
    },
    
    # EKS Extended Compliance
    "eks_cluster_encryption_secrets_enabled": {
        "mitre_mapping": "T1552 (Unsecured Credentials)",
        "compliance": "NIST 800-53 SC-28 | PCI-DSS 3.4 | SOC 2 CC6.1",
        "business_impact": "Kubernetes secrets stored unencrypted in etcd are accessible to anyone with etcd access.",
        "breach_cost_index": "Critical",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
        "remediation": [
            "Enable envelope encryption for Kubernetes secrets",
            "Create KMS key for EKS cluster encryption",
            "Update cluster encryption configuration",
            "Note: Cannot be enabled on existing clusters - requires cluster recreation"
        ]
    },
    
    # Secrets Manager Extended Compliance
    "secretsmanager_secret_unused": {
        "mitre_mapping": "T1552 (Unsecured Credentials)",
        "compliance": "NIST 800-53 AC-2 | PCI-DSS 8.1.4",
        "business_impact": "Unused secrets create unnecessary attack surface and compliance overhead.",
        "breach_cost_index": "Low",
        "nist_controls": "AC-2, IA-4",
        "pci_controls": "PCI-DSS 8.1.4",
        "iso_controls": "ISO 27001 A.9.2.6",
        "remediation": [
            "Identify secrets not accessed in 90+ days",
            "Verify secrets are truly unused via CloudTrail",
            "Delete unused secrets or schedule for deletion",
            "Document retention reasons for exceptions"
        ]
    },
    
    # WAF Extended Compliance
    "wafv2_webacl_logging_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "NIST 800-53 AU-2 | PCI-DSS 10.2.1 | SOC 2 CC7.2",
        "business_impact": "WAF logs are essential for detecting and responding to application-layer attacks.",
        "breach_cost_index": "Medium",
        "nist_controls": "AU-2, AU-3",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable WAF logging for all web ACLs",
            "Configure Kinesis Data Firehose for log delivery",
            "Set up S3 bucket or CloudWatch Logs for storage",
            "Create alarms for suspicious patterns"
        ]
    },
    
    # EFS Extended Compliance
    "efs_encryption_at_rest_enabled": {
        "mitre_mapping": "T1005 (Data from Local System)",
        "compliance": "NIST 800-53 SC-28 | PCI-DSS 3.4 | SOC 2 CC6.1",
        "business_impact": "Unencrypted EFS file systems expose data if underlying storage is compromised.",
        "breach_cost_index": "High",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
        "remediation": [
            "Enable encryption at rest on new EFS file systems",
            "Create KMS key for EFS encryption",
            "Note: Existing unencrypted file systems cannot be encrypted - requires data migration",
            "Copy data to new encrypted file system using AWS DataSync"
        ]
    },
    
    # Glue Extended Compliance
    "glue_data_catalog_encryption_enabled": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "NIST 800-53 SC-28 | PCI-DSS 3.4",
        "business_impact": "Glue Data Catalog contains metadata about data sources and schemas.",
        "breach_cost_index": "Medium",
        "nist_controls": "SC-28",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
        "remediation": [
            "Enable Data Catalog encryption in AWS Glue settings",
            "Configure KMS key for metadata encryption",
            "Enable connection password encryption",
            "Test catalog access after encryption"
        ]
    },
    
    # SageMaker Extended Compliance
    "sagemaker_notebook_instance_direct_internet_access_disabled": {
        "mitre_mapping": "T1190 (Exploit Public-Facing Application)",
        "compliance": "NIST 800-53 SC-7 | PCI-DSS 1.3.1",
        "business_impact": "Direct internet access on notebook instances increases attack surface.",
        "breach_cost_index": "High",
        "nist_controls": "SC-7, AC-4",
        "pci_controls": "PCI-DSS 1.3.1",
        "iso_controls": "ISO 27001 A.13.1.3",
        "remediation": [
            "Disable direct internet access on SageMaker notebook instances",
            "Place instances in private VPC subnets",
            "Use VPC endpoints or NAT Gateway for internet access",
            "Access notebooks via VPN or AWS PrivateLink"
        ]
    },
    
    # ElastiCache Extended Compliance
    "elasticache_redis_cluster_encryption_at_rest_enabled": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "NIST 800-53 SC-28 | PCI-DSS 3.4 | SOC 2 CC6.1",
        "business_impact": "ElastiCache often stores session data and application state requiring encryption.",
        "breach_cost_index": "High",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
        "remediation": [
            "Enable encryption at rest for ElastiCache Redis clusters",
            "Note: Requires cluster recreation",
            "Create new encrypted cluster and migrate data",
            "Update application endpoints"
        ]
    },
    
    # DocumentDB Extended Compliance
    "documentdb_cluster_log_exports_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "NIST 800-53 AU-2 | PCI-DSS 10.2.1",
        "business_impact": "DocumentDB audit logs track database operations for security analysis.",
        "breach_cost_index": "Medium",
        "nist_controls": "AU-2, AU-3",
        "pci_controls": "PCI-DSS 10.2.1",
        "iso_controls": "ISO 27001 A.12.4.1",
        "remediation": [
            "Enable audit log export to CloudWatch Logs",
            "Configure log retention period",
            "Enable profiler logs for slow query analysis",
            "Set up CloudWatch alarms for suspicious activity"
        ]
    },
    
    # CodeBuild Extended Compliance
    "codebuild_project_no_secrets_in_variables": {
        "mitre_mapping": "T1552.001 (Unsecured Credentials: Credentials In Files)",
        "compliance": "NIST 800-53 IA-5(7) | PCI-DSS 8.2.1 | SOC 2 CC6.1",
        "business_impact": "CodeBuild environment variables are visible in console and logs.",
        "breach_cost_index": "Critical",
        "nist_controls": "IA-5(7), SC-12",
        "pci_controls": "PCI-DSS 8.2.1",
        "iso_controls": "ISO 27001 A.9.4.3",
        "remediation": [
            "Remove secrets from CodeBuild environment variables",
            "Use AWS Secrets Manager or Parameter Store (SecureString)",
            "Reference secrets using parameter-store or secrets-manager type",
            "Rotate all exposed secrets immediately"
        ]
    },
}

print(f"[COMPLIANCE_BATCH_5] Added {len(COMPLIANCE_BATCH_5)} additional compliance mappings")

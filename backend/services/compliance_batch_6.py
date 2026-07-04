"""
Compliance Batch 6: Additional Security Framework Mappings
Extends compliance coverage for advanced AWS security checks
"""

COMPLIANCE_BATCH_6 = {
    "kms_key_not_publicly_accessible": {
        "mitre_mapping": "T1552 (Unsecured Credentials)",
        "compliance": "AWS FSBP KMS.1 | NIST 800-53 SC-12 | PCI-DSS 3.4",
        "nist_controls": "SC-12, AC-3",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.2",
    },
    
    "sns_topics_not_publicly_accessible": {
        "mitre_mapping": "T1071.001 (Application Layer Protocol: Web Protocols)",
        "compliance": "AWS FSBP SNS.1 | NIST 800-53 AC-3 | PCI-DSS 1.3.4",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 1.3.4",
        "iso_controls": "ISO 27001 A.9.4.1",
    },
    
    "sqs_queues_not_publicly_accessible": {
        "mitre_mapping": "T1071.001 (Application Layer Protocol: Web Protocols)",
        "compliance": "AWS FSBP SQS.1 | NIST 800-53 AC-3 | PCI-DSS 1.3.4",
        "nist_controls": "AC-3, AC-6",
        "pci_controls": "PCI-DSS 1.3.4",
        "iso_controls": "ISO 27001 A.9.4.1",
    },
    
    "efs_encryption_at_rest_enabled": {
        "mitre_mapping": "T1005 (Data from Local System)",
        "compliance": "AWS FSBP EFS.1 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "elasticsearch_domain_node_to_node_encryption": {
        "mitre_mapping": "T1040 (Network Sniffing)",
        "compliance": "AWS FSBP ES.3 | NIST 800-53 SC-8 | PCI-DSS 4.1",
        "nist_controls": "SC-8, SC-13",
        "pci_controls": "PCI-DSS 4.1",
        "iso_controls": "ISO 27001 A.13.1.1",
    },
    
    "vpc_subnet_auto_assign_public_ip_disabled": {
        "mitre_mapping": "T1190 (Exploit Public-Facing Application)",
        "compliance": "AWS FSBP EC2.15 | NIST 800-53 SC-7 | PCI-DSS 1.3.1",
        "nist_controls": "SC-7, AC-4",
        "pci_controls": "PCI-DSS 1.3.1",
        "iso_controls": "ISO 27001 A.13.1.3",
    },
    
    "guardduty_enabled_all_regions": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "CIS AWS 3.1 | NIST 800-53 SI-4 | PCI-DSS 10.6 | SOC 2 CC7.2",
        "nist_controls": "SI-4, IR-4",
        "pci_controls": "PCI-DSS 10.6",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "accessanalyzer_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "AWS FSBP IAM.21 | NIST 800-53 AC-2 | SOC 2 CC6.1",
        "nist_controls": "AC-2, AC-6",
        "pci_controls": "PCI-DSS 7.1",
        "iso_controls": "ISO 27001 A.9.2.1",
    },
    
    "macie_is_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "AWS Best Practices | NIST 800-53 SI-4 | PCI-DSS 3.4 | SOC 2 CC7.2",
        "nist_controls": "SI-4, AC-6",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.18.1.3",
    },
    
    "sagemaker_notebook_instance_encryption_enabled": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "AWS FSBP SageMaker.1 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "elasticache_redis_cluster_encryption_at_rest": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "AWS FSBP ElastiCache.2 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "codebuild_project_no_secrets_in_variables": {
        "mitre_mapping": "T1552.001 (Unsecured Credentials: Credentials In Files)",
        "compliance": "AWS FSBP CodeBuild.2 | NIST 800-53 IA-5 | PCI-DSS 8.2.1",
        "nist_controls": "IA-5, SC-28",
        "pci_controls": "PCI-DSS 8.2.1",
        "iso_controls": "ISO 27001 A.9.4.3",
    },
    
    "wafv2_webacl_logging_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "AWS FSBP WAF.1 | NIST 800-53 AU-6 | PCI-DSS 10.6",
        "nist_controls": "AU-6, SI-4",
        "pci_controls": "PCI-DSS 10.6",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "eks_cluster_encryption_secrets_enabled": {
        "mitre_mapping": "T1552 (Unsecured Credentials)",
        "compliance": "AWS FSBP EKS.1 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "cloudtrail_multi_region_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "CIS AWS 3.1 | NIST 800-53 AU-6 | PCI-DSS 10.1 | SOC 2 CC7.2",
        "nist_controls": "AU-6, AU-12",
        "pci_controls": "PCI-DSS 10.1",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "config_enabled_all_regions": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "CIS AWS 3.5 | NIST 800-53 CM-8 | PCI-DSS 11.5 | SOC 2 CC7.2",
        "nist_controls": "CM-8, CM-3",
        "pci_controls": "PCI-DSS 11.5",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "securityhub_enabled": {
        "mitre_mapping": "T1562 (Impair Defenses)",
        "compliance": "AWS Best Practices | NIST 800-53 SI-4 | PCI-DSS 10.6 | SOC 2 CC7.2",
        "nist_controls": "SI-4, RA-5",
        "pci_controls": "PCI-DSS 10.6, 11.2",
        "iso_controls": "ISO 27001 A.12.6.1",
    },
    
    "emr_cluster_kerberos_enabled": {
        "mitre_mapping": "T1078 (Valid Accounts)",
        "compliance": "AWS FSBP EMR.5 | NIST 800-53 IA-2 | PCI-DSS 8.3",
        "nist_controls": "IA-2, IA-5",
        "pci_controls": "PCI-DSS 8.3",
        "iso_controls": "ISO 27001 A.9.2.1",
    },
    
    "neptune_cluster_iam_authentication_enabled": {
        "mitre_mapping": "T1078.004 (Valid Accounts: Cloud Accounts)",
        "compliance": "AWS FSBP Neptune.2 | NIST 800-53 IA-2 | PCI-DSS 8.3",
        "nist_controls": "IA-2, AC-3",
        "pci_controls": "PCI-DSS 8.3",
        "iso_controls": "ISO 27001 A.9.2.1",
    },
    
    "documentdb_cluster_audit_logging_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "AWS FSBP DocumentDB.4 | NIST 800-53 AU-6 | PCI-DSS 10.2.7",
        "nist_controls": "AU-6, AU-12",
        "pci_controls": "PCI-DSS 10.2.7",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "athena_workgroup_encryption_enabled": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "AWS FSBP Athena.1 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "glue_data_catalog_encryption_enabled": {
        "mitre_mapping": "T1213 (Data from Information Repositories)",
        "compliance": "AWS FSBP Glue.1 | NIST 800-53 SC-28 | PCI-DSS 3.4",
        "nist_controls": "SC-28, SC-13",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.10.1.1",
    },
    
    "api_gateway_xray_tracing_enabled": {
        "mitre_mapping": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
        "compliance": "AWS FSBP APIGateway.1 | NIST 800-53 AU-6 | SOC 2 CC7.2",
        "nist_controls": "AU-6, SI-4",
        "pci_controls": "PCI-DSS 10.3",
        "iso_controls": "ISO 27001 A.12.4.1",
    },
    
    "cloudfront_distribution_encryption_in_transit": {
        "mitre_mapping": "T1040 (Network Sniffing)",
        "compliance": "AWS FSBP CloudFront.1 | NIST 800-53 SC-8 | PCI-DSS 4.1",
        "nist_controls": "SC-8, SC-13",
        "pci_controls": "PCI-DSS 4.1",
        "iso_controls": "ISO 27001 A.13.1.1",
    },
    
    "msk_cluster_encryption_in_transit": {
        "mitre_mapping": "T1040 (Network Sniffing)",
        "compliance": "AWS FSBP MSK.1 | NIST 800-53 SC-8 | PCI-DSS 4.1",
        "nist_controls": "SC-8, SC-13",
        "pci_controls": "PCI-DSS 4.1",
        "iso_controls": "ISO 27001 A.13.1.1",
    },
    
    "rds_instance_deletion_protection": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "AWS FSBP RDS.8 | NIST 800-53 CP-9 | PCI-DSS 3.4",
        "nist_controls": "CP-9, CM-3",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
    },
    
    "s3_bucket_replication_enabled": {
        "mitre_mapping": "T1485 (Data Destruction)",
        "compliance": "AWS Best Practices | NIST 800-53 CP-9 | PCI-DSS 3.4 | SOC 2 CC5.1",
        "nist_controls": "CP-9, SI-12",
        "pci_controls": "PCI-DSS 3.4",
        "iso_controls": "ISO 27001 A.12.3.1",
    },
    
    "ec2_instance_imdsv2_enabled": {
        "mitre_mapping": "T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)",
        "compliance": "AWS FSBP EC2.8 | NIST 800-53 AC-3 | PCI-DSS 2.2.4",
        "nist_controls": "AC-3, SC-7",
        "pci_controls": "PCI-DSS 2.2.4",
        "iso_controls": "ISO 27001 A.9.4.1",
    },
    
    "lambda_function_concurrent_execution_limit": {
        "mitre_mapping": "T1499 (Endpoint Denial of Service)",
        "compliance": "AWS Best Practices | NIST 800-53 SC-5",
        "nist_controls": "SC-5",
        "pci_controls": "PCI-DSS 6.6",
        "iso_controls": "ISO 27001 A.12.2.1",
    },
    
    "rds_cluster_multi_az_enabled": {
        "mitre_mapping": "T1499 (Endpoint Denial of Service)",
        "compliance": "AWS Best Practices | NIST 800-53 CP-9 | SOC 2 CC5.1",
        "nist_controls": "CP-9, CP-10",
        "pci_controls": "PCI-DSS 2.2",
        "iso_controls": "ISO 27001 A.17.2.1",
    },
}

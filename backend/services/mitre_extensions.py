"""
STEP 1.1: MITRE ATT&CK MAPPING EXTENSIONS
Additional mappings for Prowler checks not yet covered in parser_enterprise.py
These will be appended to the existing MITRE_ATTACK_MAP dictionary.
"""

# MITRE ATT&CK MAPPING EXTENSIONS - Additional 100+ checks
MITRE_EXTENSIONS = {
    # IAM Extended Coverage
    "iam_no_root_access_key": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_rotate_access_key_90_days": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_user_hardware_mfa_enabled": "T1556.006 (Modify Authentication Mechanism: Multi-Factor Authentication)",
    "iam_support_role_exists": "T1098 (Account Manipulation)",
    "iam_policy_attached_only_to_group_or_roles": "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "iam_policy_no_wildcards": "T1098.001 (Account Manipulation: Additional Cloud Credentials)",
    "iam_no_custom_policy_permissive_role_assumption": "T1098 (Account Manipulation)",
    "iam_credentials_last_used_90_days": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "iam_avoid_root_usage": "T1078.004 (Valid Accounts: Cloud Accounts)",
    
    # S3 Extended Coverage
    "s3_bucket_acl_prohibited": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_object_lock_enabled": "T1485 (Data Destruction)",
    "s3_bucket_lifecycle_policy_enabled": "T1485 (Data Destruction)",
    "s3_bucket_kms_encryption_enabled": "T1213 (Data from Information Repositories)",
    "s3_bucket_acl_no_public_read": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_acl_no_public_write": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_policy_no_wildcard_principal": "T1530 (Data from Cloud Storage Object)",
    "s3_bucket_server_access_logging_enabled": "T1070.004 (Indicator Removal: File Deletion)",
    "s3_bucket_default_encryption_enabled": "T1213 (Data from Information Repositories)",
    
    # EC2 Extended Coverage
    "ec2_instance_managed_by_ssm": "T1078 (Valid Accounts)",
    "ec2_instance_profile_attached": "T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)",
    "ec2_ebs_default_encryption_enabled": "T1005 (Data from Local System)",
    "ec2_ami_encryption_enabled": "T1525 (Implant Internal Image)",
    "ec2_ami_public": "T1525 (Implant Internal Image)",
    "ec2_networkacl_unrestricted_ingress_22": "T1021.004 (Remote Services: SSH)",
    "ec2_networkacl_unrestricted_ingress_3389": "T1021.001 (Remote Services: Remote Desktop Protocol)",
    "ec2_ebs_snapshot_encryption_enabled": "T1005 (Data from Local System)",
    "ec2_instance_termination_protection": "T1499 (Endpoint Denial of Service)",
    "ec2_instance_detailed_monitoring_enabled": "T1562 (Impair Defenses)",
    
    # RDS Extended Coverage
    "rds_instance_minor_version_upgrade_enabled": "T1190 (Exploit Public-Facing Application)",
    "rds_instance_copy_tags_to_snapshots": "T1530 (Data from Cloud Storage Object)",
    "rds_instance_iam_authentication_enabled": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "rds_instance_enhanced_monitoring_enabled": "T1562 (Impair Defenses)",
    "rds_instance_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "rds_cluster_deletion_protection": "T1485 (Data Destruction)",
    "rds_snapshots_encrypted": "T1005 (Data from Local System)",
    
    # VPC Extended Coverage
    "vpc_peering_routing_tables_least_privilege": "T1046 (Network Service Discovery)",
    "vpc_subnet_auto_assign_public_ip_disabled": "T1190 (Exploit Public-Facing Application)",
    "vpc_endpoint_services_allowed_principals_trust_boundaries": "T1133 (External Remote Services)",
    "vpc_different_regions": "T1499 (Endpoint Denial of Service)",
    
    # CloudWatch Extended Coverage
    "cloudwatch_log_metric_filter_authentication_failures": "T1110 (Brute Force)",
    "cloudwatch_log_metric_filter_root_usage": "T1078.004 (Valid Accounts: Cloud Accounts)",
    "cloudwatch_log_metric_filter_unauthorized_api_calls": "T1078 (Valid Accounts)",
    "cloudwatch_log_metric_filter_cloudtrail_configuration_changes": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "cloudwatch_log_metric_filter_console_authentication_failures": "T1110 (Brute Force)",
    "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk": "T1485 (Data Destruction)",
    "cloudwatch_log_metric_filter_s3_bucket_policy_changes": "T1530 (Data from Cloud Storage Object)",
    "cloudwatch_log_metric_filter_aws_config_configuration_changes": "T1562 (Impair Defenses)",
    "cloudwatch_log_metric_filter_security_group_changes": "T1562 (Impair Defenses)",
    "cloudwatch_log_metric_filter_nacl_changes": "T1562 (Impair Defenses)",
    "cloudwatch_log_metric_filter_network_gateway_changes": "T1562 (Impair Defenses)",
    "cloudwatch_log_metric_filter_route_table_changes": "T1562 (Impair Defenses)",
    "cloudwatch_log_metric_filter_vpc_changes": "T1562 (Impair Defenses)",
    
    # Lambda Extended Coverage
    "lambda_function_not_publicly_accessible": "T1190 (Exploit Public-Facing Application)",
    "lambda_function_invoke_api_operations_cloudtrail_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "lambda_function_using_supported_runtimes": "T1203 (Exploitation for Client Execution)",
    "lambda_function_no_secrets_in_code": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    "lambda_function_no_secrets_in_variables": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    
    # ELB Extended Coverage
    "elb_cross_zone_load_balancing_enabled": "T1499 (Endpoint Denial of Service)",
    "elb_desync_mitigation_mode": "T1499 (Endpoint Denial of Service)",
    "elbv2_waf_acl_attached": "T1190 (Exploit Public-Facing Application)",
    "elbv2_drop_invalid_header_fields": "T1071.001 (Application Layer Protocol: Web Protocols)",
    
    # KMS Extended Coverage
    "kms_key_not_publicly_accessible": "T1552 (Unsecured Credentials)",
    "kms_key_policy_no_wildcard_principal": "T1552 (Unsecured Credentials)",
    
    # SNS Extended Coverage
    "sns_topics_not_publicly_accessible": "T1071.001 (Application Layer Protocol: Web Protocols)",
    "sns_topics_kms_encryption_at_rest_enabled": "T1213 (Data from Information Repositories)",
    
    # SQS Extended Coverage
    "sqs_queues_not_publicly_accessible": "T1071.001 (Application Layer Protocol: Web Protocols)",
    "sqs_queues_kms_encryption_at_rest_enabled": "T1213 (Data from Information Repositories)",
    "sqs_queues_server_side_encryption_enabled": "T1213 (Data from Information Repositories)",
    
    # DynamoDB Extended Coverage
    "dynamodb_tables_pitr_enabled": "T1485 (Data Destruction)",
    "dynamodb_table_auto_scaling_enabled": "T1499 (Endpoint Denial of Service)",
    
    # Redshift Extended Coverage
    "redshift_cluster_automated_snapshot": "T1485 (Data Destruction)",
    "redshift_cluster_audit_logging": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "redshift_cluster_enhanced_vpc_routing_enabled": "T1133 (External Remote Services)",
    "redshift_cluster_automatic_upgrades": "T1190 (Exploit Public-Facing Application)",
    
    # Elasticsearch/OpenSearch Extended Coverage
    "es_domain_node_to_node_encryption_enabled": "T1040 (Network Sniffing)",
    "es_domain_https_required": "T1040 (Network Sniffing)",
    "es_domain_not_publicly_accessible": "T1190 (Exploit Public-Facing Application)",
    "es_domain_audit_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "opensearch_service_domains_node_to_node_encryption_enabled": "T1040 (Network Sniffing)",
    "opensearch_service_domains_https_required": "T1040 (Network Sniffing)",
    "opensearch_service_domains_audit_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    
    # ACM Extended Coverage
    "acm_certificates_transparency_logs_enabled": "T1588.004 (Obtain Capabilities: Digital Certificates)",
    "acm_certificates_rsa_key_length": "T1040 (Network Sniffing)",
    
    # API Gateway Extended Coverage
    "apigateway_restapi_waf_acl_attached": "T1190 (Exploit Public-Facing Application)",
    "apigateway_authorizers_enabled": "T1078 (Valid Accounts)",
    "apigateway_client_certificate_enabled": "T1071.001 (Application Layer Protocol: Web Protocols)",
    
    # ECS Extended Coverage
    "ecs_task_definition_no_privileged_containers": "T1611 (Escape to Host)",
    "ecs_task_definition_pid_mode_check": "T1611 (Escape to Host)",
    "ecs_task_definition_network_mode": "T1133 (External Remote Services)",
    "ecs_service_load_balancer_is_internet_facing": "T1190 (Exploit Public-Facing Application)",
    
    # EKS Extended Coverage
    "eks_cluster_endpoint_access_restricted": "T1190 (Exploit Public-Facing Application)",
    "eks_cluster_encryption_secrets_enabled": "T1552 (Unsecured Credentials)",
    "eks_cluster_network_policy_enabled": "T1046 (Network Service Discovery)",
    
    # Secrets Manager Extended Coverage
    "secretsmanager_secret_unused": "T1552 (Unsecured Credentials)",
    "secretsmanager_secret_not_used_90_days": "T1552 (Unsecured Credentials)",
    
    # SSM Extended Coverage
    "ssm_managed_compliant_patching": "T1203 (Exploitation for Client Execution)",
    "ssm_managed_compliant_association": "T1078 (Valid Accounts)",
    "ssm_document_not_public": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    
    # AWS Account Extended Coverage
    "account_security_contact_information_is_registered": "T1078 (Valid Accounts)",
    "account_maintain_current_contact_details": "T1078 (Valid Accounts)",
    "account_security_questions_registered": "T1078 (Valid Accounts)",
    
    # Access Analyzer Extended Coverage
    "accessanalyzer_enabled": "T1562 (Impair Defenses)",
    
    # Organizations Extended Coverage
    "organizations_scp_check_deny_regions": "T1078 (Valid Accounts)",
    
    # Macie Extended Coverage
    "macie_is_enabled": "T1562 (Impair Defenses)",
    
    # Inspector Extended Coverage
    "inspector_is_enabled": "T1562 (Impair Defenses)",
    
    # Shield Extended Coverage
    "shield_advanced_enabled_on_resources": "T1499 (Endpoint Denial of Service)",
    
    # WAF Extended Coverage
    "waf_regional_rule_with_conditions": "T1190 (Exploit Public-Facing Application)",
    "wafv2_webacl_with_rules": "T1190 (Exploit Public-Facing Application)",
    "wafv2_webacl_logging_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    
    # EFS Extended Coverage
    "efs_encryption_at_rest_enabled": "T1005 (Data from Local System)",
    "efs_have_backup_enabled": "T1485 (Data Destruction)",
    
    # Glacier Extended Coverage
    "glacier_vault_access_policy_not_public": "T1530 (Data from Cloud Storage Object)",
    
    # Glue Extended Coverage
    "glue_data_catalog_encryption_enabled": "T1213 (Data from Information Repositories)",
    "glue_development_endpoint_cloudwatch_logs_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    "glue_development_endpoint_job_bookmark_encryption_enabled": "T1213 (Data from Information Repositories)",
    "glue_development_endpoint_s3_encryption_enabled": "T1213 (Data from Information Repositories)",
    
    # SageMaker Extended Coverage
    "sagemaker_notebook_instance_encryption_enabled": "T1213 (Data from Information Repositories)",
    "sagemaker_notebook_instance_vpc_settings_configured": "T1133 (External Remote Services)",
    "sagemaker_notebook_instance_direct_internet_access_disabled": "T1190 (Exploit Public-Facing Application)",
    "sagemaker_training_jobs_network_isolation_enabled": "T1133 (External Remote Services)",
    
    # Athena Extended Coverage
    "athena_workgroup_encryption": "T1213 (Data from Information Repositories)",
    "athena_workgroup_enforce_configuration": "T1078 (Valid Accounts)",
    
    # EMR Extended Coverage
    "emr_cluster_master_nodes_no_public_ip": "T1190 (Exploit Public-Facing Application)",
    "emr_cluster_kerberos_enabled": "T1078 (Valid Accounts)",
    
    # ElastiCache Extended Coverage
    "elasticache_redis_cluster_encryption_at_rest_enabled": "T1213 (Data from Information Repositories)",
    "elasticache_redis_cluster_encryption_at_transit_enabled": "T1040 (Network Sniffing)",
    "elasticache_redis_cluster_auto_backup_enabled": "T1485 (Data Destruction)",
    
    # Neptune Extended Coverage
    "neptune_cluster_backup_retention_check": "T1485 (Data Destruction)",
    "neptune_cluster_encrypted": "T1213 (Data from Information Repositories)",
    "neptune_cluster_snapshot_encryption": "T1213 (Data from Information Repositories)",
    
    # DAX Extended Coverage
    "dax_cluster_encryption_enabled": "T1213 (Data from Information Repositories)",
    
    # DocumentDB Extended Coverage
    "documentdb_cluster_backup_retention_check": "T1485 (Data Destruction)",
    "documentdb_cluster_encrypted": "T1213 (Data from Information Repositories)",
    "documentdb_cluster_log_exports_enabled": "T1562.008 (Impair Defenses: Disable Cloud Logs)",
    
    # CodeBuild Extended Coverage
    "codebuild_project_no_secrets_in_variables": "T1552.001 (Unsecured Credentials: Credentials In Files)",
    "codebuild_project_s3_logs_encryption_enabled": "T1213 (Data from Information Repositories)",
    "codebuild_project_user_controlled_buildspec": "T1525 (Implant Internal Image)",
}

# Mapping Statistics
print(f"[MITRE EXTENSIONS] Added {len(MITRE_EXTENSIONS)} additional check_id mappings")
print(f"[MITRE EXTENSIONS] Total coverage with existing mappings: ~{200 + len(MITRE_EXTENSIONS)} checks")

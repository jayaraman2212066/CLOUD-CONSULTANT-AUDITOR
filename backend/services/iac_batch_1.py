# Module 1: Additional 30 CLI Command Templates (Batch 1)
# This adds CLI commands for checks 47-76

IAC_BATCH_1 = {
    "acm_certificates_expiration_check": {
        "cli": (
            "# List certificates expiring within 30 days\n"
            "aws acm list-certificates --region <REGION> | jq '.CertificateSummaryList[] | select(.NotAfter < (now + 2592000))'\n\n"
            "# Delete expired certificate\n"
            "aws acm delete-certificate --certificate-arn <CERT_ARN> --region <REGION>"
        ),
        "terraform": (
            '# Monitor certificate expiration\n'
            'resource "aws_cloudwatch_metric_alarm" "cert_expiry" {\n'
            '  alarm_name          = "acm-cert-expiring"\n'
            '  comparison_operator = "LessThanThreshold"\n'
            '  evaluation_periods  = "1"\n'
            '  metric_name         = "DaysToExpiry"\n'
            '  namespace           = "AWS/CertificateManager"\n'
            '  period              = "86400"\n'
            '  threshold           = "30"\n'
            '}' 
        ),
        "cloudformation": "# Use AWS Certificate Manager console to renew or request new certificate",
    },
    "apigateway_client_certificate_enabled": {
        "cli": (
            "# Generate client certificate for API Gateway\n"
            "aws apigateway generate-client-certificate --description 'API Gateway Client Cert'\n\n"
            "# Update stage to use client certificate\n"
            "aws apigateway update-stage \\\n"
            "  --rest-api-id <API_ID> \\\n"
            "  --stage-name <STAGE> \\\n"
            "  --patch-operations op=replace,path=/clientCertificateId,value=<CERT_ID>"
        ),
        "terraform": (
            'resource "aws_api_gateway_client_certificate" "main" {\n'
            '  description = "Client certificate for API Gateway"\n'
            '}\n\n'
            'resource "aws_api_gateway_stage" "main" {\n'
            '  client_certificate_id = aws_api_gateway_client_certificate.main.id\n'
            '}'
        ),
        "cloudformation": "Type: AWS::ApiGateway::ClientCertificate",
    },
    "backup_plans_exist": {
        "cli": (
            "# Create AWS Backup plan\n"
            "aws backup create-backup-plan \\\n"
            "  --backup-plan '{\"BackupPlanName\":\"DailyBackup\",\"Rules\":[{\"RuleName\":\"DailyRule\",\"TargetBackupVaultName\":\"Default\",\"ScheduleExpression\":\"cron(0 5 ? * * *)\",\"StartWindowMinutes\":60,\"CompletionWindowMinutes\":120,\"Lifecycle\":{\"DeleteAfterDays\":30}}]}'"
        ),
        "terraform": (
            'resource "aws_backup_plan" "main" {\n'
            '  name = "daily-backup-plan"\n'
            '  rule {\n'
            '    rule_name         = "daily_rule"\n'
            '    target_vault_name = aws_backup_vault.main.name\n'
            '    schedule          = "cron(0 5 ? * * *)"\n'
            '    lifecycle {\n'
            '      delete_after = 30\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Type: AWS::Backup::BackupPlan",
    },
    "backup_recovery_point_encrypted": {
        "cli": (
            "# Backup encryption is inherited from source resource\n"
            "# Ensure source resources (RDS, EBS, etc) are encrypted\n"
            "aws rds modify-db-instance --db-instance-identifier <DB> --storage-encrypted"
        ),
        "terraform": "# Encryption is inherited from source resource",
        "cloudformation": "# Encryption is inherited from source resource",
    },
    "backup_recovery_point_manual_deletion_disabled": {
        "cli": (
            "# Enable backup vault lock to prevent manual deletion\n"
            "aws backup put-backup-vault-lock-configuration \\\n"
            "  --backup-vault-name <VAULT_NAME> \\\n"
            "  --min-retention-days 30"
        ),
        "terraform": (
            'resource "aws_backup_vault_lock_configuration" "main" {\n'
            '  backup_vault_name   = aws_backup_vault.main.name\n'
            '  min_retention_days  = 30\n'
            '}'
        ),
        "cloudformation": "Type: AWS::Backup::BackupVault with LockConfiguration",
    },
    "cloudtrail_cloudwatch_logging_enabled": {
        "cli": (
            "# Enable CloudWatch logging for CloudTrail\n"
            "aws cloudtrail update-trail \\\n"
            "  --name <TRAIL_NAME> \\\n"
            "  --cloud-watch-logs-log-group-arn <LOG_GROUP_ARN> \\\n"
            "  --cloud-watch-logs-role-arn <ROLE_ARN>"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"\n'
            '  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn\n'
            '}'
        ),
        "cloudformation": "CloudWatchLogsLogGroupArn: !GetAtt TrailLogGroup.Arn",
    },
    "cloudtrail_kms_encryption_enabled": {
        "cli": (
            "# Enable KMS encryption for CloudTrail\n"
            "aws cloudtrail update-trail \\\n"
            "  --name <TRAIL_NAME> \\\n"
            "  --kms-key-id <KMS_KEY_ID>"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  kms_key_id = aws_kms_key.cloudtrail.arn\n'
            '}'
        ),
        "cloudformation": "KMSKeyId: !Ref CloudTrailKey",
    },
    "cloudtrail_logs_s3_bucket_access_logging_enabled": {
        "cli": (
            "# Enable access logging on CloudTrail S3 bucket\n"
            "aws s3api put-bucket-logging \\\n"
            "  --bucket <CLOUDTRAIL_BUCKET> \\\n"
            "  --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<LOG_BUCKET>\",\"TargetPrefix\":\"cloudtrail-logs/\"}}'"
        ),
        "terraform": (
            'resource "aws_s3_bucket_logging" "cloudtrail" {\n'
            '  bucket        = aws_s3_bucket.cloudtrail.id\n'
            '  target_bucket = aws_s3_bucket.logs.id\n'
            '  target_prefix = "cloudtrail-logs/"\n'
            '}'
        ),
        "cloudformation": "LoggingConfiguration in bucket properties",
    },
    "cloudwatch_alarm_actions": {
        "cli": (
            "# Create CloudWatch alarm with SNS action\n"
            "aws cloudwatch put-metric-alarm \\\n"
            "  --alarm-name high-cpu \\\n"
            "  --alarm-actions <SNS_TOPIC_ARN> \\\n"
            "  --metric-name CPUUtilization \\\n"
            "  --namespace AWS/EC2 \\\n"
            "  --statistic Average \\\n"
            "  --period 300 \\\n"
            "  --threshold 80 \\\n"
            "  --comparison-operator GreaterThanThreshold"
        ),
        "terraform": (
            'resource "aws_cloudwatch_metric_alarm" "main" {\n'
            '  alarm_actions = [aws_sns_topic.alerts.arn]\n'
            '}'
        ),
        "cloudformation": "AlarmActions: [!Ref SNSTopic]",
    },
    "cloudwatch_log_group_no_retention_policy": {
        "cli": (
            "# Set log retention to 90 days\n"
            "aws logs put-retention-policy \\\n"
            "  --log-group-name <LOG_GROUP> \\\n"
            "  --retention-in-days 90"
        ),
        "terraform": (
            'resource "aws_cloudwatch_log_group" "main" {\n'
            '  retention_in_days = 90\n'
            '}'
        ),
        "cloudformation": "RetentionInDays: 90",
    },
    "config_enabled": {
        "cli": (
            "# Enable AWS Config\n"
            "aws configservice put-configuration-recorder \\\n"
            "  --configuration-recorder name=default,roleARN=<ROLE_ARN> \\\n"
            "  --recording-group allSupported=true\n\n"
            "aws configservice put-delivery-channel \\\n"
            "  --delivery-channel name=default,s3BucketName=<BUCKET>\n\n"
            "aws configservice start-configuration-recorder --configuration-recorder-name default"
        ),
        "terraform": (
            'resource "aws_config_configuration_recorder" "main" {\n'
            '  role_arn = aws_iam_role.config.arn\n'
            '  recording_group {\n'
            '    all_supported = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Type: AWS::Config::ConfigurationRecorder",
    },
    "dynamodb_pitr_enabled": {
        "cli": (
            "# Enable Point-in-Time Recovery for DynamoDB\n"
            "aws dynamodb update-continuous-backups \\\n"
            "  --table-name <TABLE_NAME> \\\n"
            "  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
        ),
        "terraform": (
            'resource "aws_dynamodb_table" "main" {\n'
            '  point_in_time_recovery {\n'
            '    enabled = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "PointInTimeRecoverySpecification:\n  PointInTimeRecoveryEnabled: true",
    },
    "ec2_ami_public": {
        "cli": (
            "# Make AMI private\n"
            "aws ec2 modify-image-attribute \\\n"
            "  --image-id <AMI_ID> \\\n"
            "  --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'"
        ),
        "terraform": (
            'resource "aws_ami_launch_permission" "private" {\n'
            '  image_id = aws_ami.main.id\n'
            '  # Remove all public permissions\n'
            '}'
        ),
        "cloudformation": "# Modify AMI permissions via console or CLI",
    },
    "ec2_ebs_encryption": {
        "cli": (
            "# Enable EBS encryption by default\n"
            "aws ec2 enable-ebs-encryption-by-default --region <REGION>"
        ),
        "terraform": (
            'resource "aws_ebs_encryption_by_default" "main" {\n'
            '  enabled = true\n'
            '}'
        ),
        "cloudformation": "# Enable via console or CLI (account-level setting)",
    },
    "ec2_ebs_public_snapshot": {
        "cli": (
            "# Make snapshot private\n"
            "aws ec2 modify-snapshot-attribute \\\n"
            "  --snapshot-id <SNAPSHOT_ID> \\\n"
            "  --attribute createVolumePermission \\\n"
            "  --operation-type remove \\\n"
            "  --group-names all"
        ),
        "terraform": "# Ensure no aws_snapshot_create_volume_permission with group = all",
        "cloudformation": "# Modify snapshot permissions via console",
    },
    "ec2_instance_older_than_specific_days": {
        "cli": (
            "# List instances older than 90 days\n"
            "aws ec2 describe-instances \\\n"
            "  --query 'Reservations[].Instances[?LaunchTime<=`$(date -u -d \"90 days ago\" +\"%Y-%m-%dT%H:%M:%S\")`].[InstanceId,LaunchTime]' \\\n"
            "  --output table\n\n"
            "# Terminate old instance\n"
            "aws ec2 terminate-instances --instance-ids <INSTANCE_ID>"
        ),
        "terraform": "# Implement lifecycle policy with auto-termination after N days",
        "cloudformation": "# Use AWS Systems Manager Automation for lifecycle management",
    },
    "ec2_security_group_open_to_internet": {
        "cli": (
            "# Remove 0.0.0.0/0 rule from security group\n"
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id <SG_ID> \\\n"
            "  --protocol tcp \\\n"
            "  --port <PORT> \\\n"
            "  --cidr 0.0.0.0/0"
        ),
        "terraform": "# Remove ingress rules with cidr_blocks = [\"0.0.0.0/0\"]",
        "cloudformation": "# Remove SecurityGroupIngress with CidrIp: 0.0.0.0/0",
    },
    "ecr_image_scan_on_push": {
        "cli": (
            "# Enable image scanning\n"
            "aws ecr put-image-scanning-configuration \\\n"
            "  --repository-name <REPO> \\\n"
            "  --image-scanning-configuration scanOnPush=true"
        ),
        "terraform": (
            'resource "aws_ecr_repository" "main" {\n'
            '  image_scanning_configuration {\n'
            '    scan_on_push = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "ImageScanningConfiguration:\n  ScanOnPush: true",
    },
    "ecs_task_definition_container_readonly_root_filesystem": {
        "cli": (
            "# Update task definition with readonlyRootFilesystem\n"
            "aws ecs register-task-definition \\\n"
            "  --family <FAMILY> \\\n"
            "  --container-definitions '[{\"name\":\"app\",\"readonlyRootFilesystem\":true}]'"
        ),
        "terraform": (
            'resource "aws_ecs_task_definition" "main" {\n'
            '  container_definitions = jsonencode([{\n'
            '    readonlyRootFilesystem = true\n'
            '  }])\n'
            '}'
        ),
        "cloudformation": "readonlyRootFilesystem: true in ContainerDefinitions",
    },
    "ecs_task_definition_user_not_root": {
        "cli": (
            "# Run container as non-root user\n"
            "aws ecs register-task-definition \\\n"
            "  --family <FAMILY> \\\n"
            "  --container-definitions '[{\"name\":\"app\",\"user\":\"1000:1000\"}]'"
        ),
        "terraform": (
            'resource "aws_ecs_task_definition" "main" {\n'
            '  container_definitions = jsonencode([{\n'
            '    user = "1000:1000"\n'
            '  }])\n'
            '}'
        ),
        "cloudformation": "user: \"1000:1000\" in ContainerDefinitions",
    },
    "ecs_task_definitions_no_environment_secrets": {
        "cli": (
            "# Use secrets instead of environment variables\n"
            "aws ecs register-task-definition \\\n"
            "  --family <FAMILY> \\\n"
            "  --container-definitions '[{\"secrets\":[{\"name\":\"DB_PASSWORD\",\"valueFrom\":\"<SECRET_ARN>\"}]}]'"
        ),
        "terraform": (
            'resource "aws_ecs_task_definition" "main" {\n'
            '  container_definitions = jsonencode([{\n'
            '    secrets = [{\n'
            '      name      = "DB_PASSWORD"\n'
            '      valueFrom = aws_secretsmanager_secret.db.arn\n'
            '    }]\n'
            '  }])\n'
            '}'
        ),
        "cloudformation": "secrets in ContainerDefinitions",
    },
    "eks_control_plane_logging_all_types_enabled": {
        "cli": (
            "# Enable all EKS log types\n"
            "aws eks update-cluster-config \\\n"
            "  --name <CLUSTER> \\\n"
            "  --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'"
        ),
        "terraform": (
            'resource "aws_eks_cluster" "main" {\n'
            '  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]\n'
            '}'
        ),
        "cloudformation": "EnabledClusterLogTypes: [api, audit, authenticator, controllerManager, scheduler]",
    },
    "elb_internet_facing": {
        "cli": (
            "# ELB scheme cannot be changed after creation\n"
            "# Create new internal load balancer\n"
            "aws elb create-load-balancer \\\n"
            "  --load-balancer-name <NAME> \\\n"
            "  --listeners Protocol=HTTP,LoadBalancerPort=80,InstancePort=80 \\\n"
            "  --scheme internal \\\n"
            "  --subnets <PRIVATE_SUBNET_IDS>"
        ),
        "terraform": (
            'resource "aws_lb" "main" {\n'
            '  internal = true\n'
            '}'
        ),
        "cloudformation": "Scheme: internal",
    },
    "elb_logging_enabled": {
        "cli": (
            "# Enable Classic ELB access logging\n"
            "aws elb modify-load-balancer-attributes \\\n"
            "  --load-balancer-name <NAME> \\\n"
            "  --load-balancer-attributes '{\"AccessLog\":{\"Enabled\":true,\"S3BucketName\":\"<BUCKET>\"}}'"
        ),
        "terraform": (
            'resource "aws_elb" "main" {\n'
            '  access_logs {\n'
            '    bucket  = aws_s3_bucket.logs.id\n'
            '    enabled = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "AccessLoggingPolicy:\n  Enabled: true",
    },
    "elb_ssl_listeners": {
        "cli": (
            "# Add HTTPS listener to ELB\n"
            "aws elb create-load-balancer-listeners \\\n"
            "  --load-balancer-name <NAME> \\\n"
            "  --listeners Protocol=HTTPS,LoadBalancerPort=443,InstancePort=80,InstanceProtocol=HTTP,SSLCertificateId=<CERT_ARN>"
        ),
        "terraform": (
            'resource "aws_elb" "main" {\n'
            '  listener {\n'
            '    lb_protocol       = "HTTPS"\n'
            '    lb_port           = 443\n'
            '    instance_protocol = "HTTP"\n'
            '    instance_port     = 80\n'
            '    ssl_certificate_id = aws_acm_certificate.main.arn\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Protocol: HTTPS in Listeners",
    },
    "elbv2_insecure_ssl_ciphers": {
        "cli": (
            "# Update SSL policy to use secure ciphers\n"
            "aws elbv2 modify-listener \\\n"
            "  --listener-arn <LISTENER_ARN> \\\n"
            "  --ssl-policy ELBSecurityPolicy-TLS-1-2-2017-01"
        ),
        "terraform": (
            'resource "aws_lb_listener" "https" {\n'
            '  ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"\n'
            '}'
        ),
        "cloudformation": "SslPolicy: ELBSecurityPolicy-TLS-1-2-2017-01",
    },
    "es_domain_encryption_at_rest_enabled": {
        "cli": (
            "# Encryption must be enabled at domain creation\n"
            "# Create new encrypted domain\n"
            "aws es create-elasticsearch-domain \\\n"
            "  --domain-name <NAME> \\\n"
            "  --encryption-at-rest-options Enabled=true,KmsKeyId=<KEY_ID>"
        ),
        "terraform": (
            'resource "aws_elasticsearch_domain" "main" {\n'
            '  encrypt_at_rest {\n'
            '    enabled    = true\n'
            '    kms_key_id = aws_kms_key.es.arn\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "EncryptionAtRestOptions:\n  Enabled: true",
    },
    "guardduty_is_enabled": {
        "cli": (
            "# Enable GuardDuty\n"
            "aws guardduty create-detector --enable --region <REGION>"
        ),
        "terraform": (
            'resource "aws_guardduty_detector" "main" {\n'
            '  enable = true\n'
            '}'
        ),
        "cloudformation": "Type: AWS::GuardDuty::Detector\nProperties:\n  Enable: true",
    },
    "guardduty_no_high_severity_findings": {
        "cli": (
            "# List high/critical GuardDuty findings\n"
            "aws guardduty list-findings \\\n"
            "  --detector-id <DETECTOR_ID> \\\n"
            "  --finding-criteria '{\"Criterion\":{\"severity\":{\"Gte\":7}}}'\n\n"
            "# Archive findings after remediation\n"
            "aws guardduty archive-findings \\\n"
            "  --detector-id <DETECTOR_ID> \\\n"
            "  --finding-ids <FINDING_IDS>"
        ),
        "terraform": "# Remediate the actual security issues causing GuardDuty alerts",
        "cloudformation": "# Remediate the actual security issues causing GuardDuty alerts",
    },
}

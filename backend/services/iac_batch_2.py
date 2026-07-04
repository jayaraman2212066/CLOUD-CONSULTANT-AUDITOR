# Module 2: Additional 27 CLI Command Templates (Batch 2)
# This completes coverage for all remaining Prowler checks

IAC_BATCH_2 = {
    "iam_inline_policy_no_administrative_privileges": {
        "cli": (
            "# Remove administrative inline policies\n"
            "aws iam delete-user-policy --user-name <USER> --policy-name <POLICY_NAME>\n"
            "aws iam delete-role-policy --role-name <ROLE> --policy-name <POLICY_NAME>\n"
            "aws iam delete-group-policy --group-name <GROUP> --policy-name <POLICY_NAME>"
        ),
        "terraform": "# Avoid inline policies, use managed policies instead",
        "cloudformation": "# Use AWS::IAM::ManagedPolicy instead of inline policies",
    },
    "iam_password_policy": {
        "cli": (
            "# Set comprehensive password policy\n"
            "aws iam update-account-password-policy \\\n"
            "  --minimum-password-length 14 \\\n"
            "  --require-symbols \\\n"
            "  --require-numbers \\\n"
            "  --require-uppercase-characters \\\n"
            "  --require-lowercase-characters \\\n"
            "  --max-password-age 90 \\\n"
            "  --password-reuse-prevention 24"
        ),
        "terraform": (
            'resource "aws_iam_account_password_policy" "strict" {\n'
            '  minimum_password_length        = 14\n'
            '  require_symbols                = true\n'
            '  require_numbers                = true\n'
            '  require_uppercase_characters   = true\n'
            '  require_lowercase_characters   = true\n'
            '  max_password_age               = 90\n'
            '  password_reuse_prevention      = 24\n'
            '}'
        ),
        "cloudformation": "# Configured at account level via console/CLI",
    },
    "iam_password_policy_reuse_24": {
        "cli": (
            "# Enable password reuse prevention\n"
            "aws iam update-account-password-policy --password-reuse-prevention 24"
        ),
        "terraform": "password_reuse_prevention = 24",
        "cloudformation": "# Configured in IAM password policy",
    },
    "iam_policy_admin_access": {
        "cli": (
            "# Detach AdministratorAccess policy\n"
            "aws iam detach-user-policy \\\n"
            "  --user-name <USER> \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
        "terraform": "# Remove aws_iam_user_policy_attachment with AdministratorAccess",
        "cloudformation": "# Remove AdministratorAccess from ManagedPolicyArns",
    },
    "iam_role_privilege_escalation": {
        "cli": (
            "# Review and restrict IAM role permissions\n"
            "aws iam get-role-policy --role-name <ROLE> --policy-name <POLICY>\n\n"
            "# Update policy to remove privilege escalation permissions\n"
            "# Remove: iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:PassRole, lambda:CreateFunction, lambda:UpdateFunctionCode"
        ),
        "terraform": "# Apply principle of least privilege to IAM role policies",
        "cloudformation": "# Review and restrict IAM role PolicyDocument",
    },
    "iam_root_access_key": {
        "cli": (
            "# Delete root account access keys (CRITICAL)\n"
            "# Login to AWS console as root user\n"
            "# Go to Security Credentials\n"
            "# Delete all access keys\n\n"
            "# List access keys\n"
            "aws iam list-access-keys --user-name root"
        ),
        "terraform": "# Root access keys cannot be managed via IaC - delete via console",
        "cloudformation": "# Root access keys cannot be managed via IaC - delete via console",
    },
    "iam_root_hardware_mfa_enabled": {
        "cli": (
            "# Hardware MFA must be enabled via AWS console\n"
            "# 1. Login as root\n"
            "# 2. Go to Security Credentials\n"
            "# 3. Assign MFA device\n"
            "# 4. Choose Hardware MFA device"
        ),
        "terraform": "# Root MFA must be configured via AWS console",
        "cloudformation": "# Root MFA must be configured via AWS console",
    },
    "iam_user_console_access_mfa": {
        "cli": (
            "# Enforce MFA for console access via IAM policy\n"
            "aws iam put-user-policy \\\n"
            "  --user-name <USER> \\\n"
            "  --policy-name ForceMFA \\\n"
            "  --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"BoolIfExists\":{\"aws:MultiFactorAuthPresent\":\"false\"}}}]}'"
        ),
        "terraform": (
            'resource "aws_iam_user_policy" "force_mfa" {\n'
            '  policy = jsonencode({\n'
            '    Statement = [{\n'
            '      Effect = "Deny"\n'
            '      Action = "*"\n'
            '      Resource = "*"\n'
            '      Condition = {\n'
            '        BoolIfExists = {"aws:MultiFactorAuthPresent" = "false"}\n'
            '      }\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": "# Apply IAM policy with MFA condition",
    },
    "iam_user_unused_credentials_90_days": {
        "cli": (
            "# List users with unused credentials > 90 days\n"
            "aws iam generate-credential-report\n"
            "aws iam get-credential-report --query 'Content' --output text | base64 -d\n\n"
            "# Deactivate unused access key\n"
            "aws iam update-access-key \\\n"
            "  --user-name <USER> \\\n"
            "  --access-key-id <KEY_ID> \\\n"
            "  --status Inactive"
        ),
        "terraform": "# Implement automated credential rotation via Lambda",
        "cloudformation": "# Implement automated credential rotation via Lambda",
    },
    "lambda_function_public_access": {
        "cli": (
            "# Remove public Lambda permission\n"
            "aws lambda remove-permission \\\n"
            "  --function-name <FUNCTION> \\\n"
            "  --statement-id AllowPublicAccess"
        ),
        "terraform": "# Remove aws_lambda_permission with Principal = \"*\"",
        "cloudformation": "# Remove AWS::Lambda::Permission with Principal: '*'",
    },
    "lambda_function_url_public": {
        "cli": (
            "# Update Lambda function URL to require IAM auth\n"
            "aws lambda update-function-url-config \\\n"
            "  --function-name <FUNCTION> \\\n"
            "  --auth-type AWS_IAM"
        ),
        "terraform": (
            'resource "aws_lambda_function_url" "main" {\n'
            '  authorization_type = "AWS_IAM"\n'
            '}'
        ),
        "cloudformation": "AuthorizationType: AWS_IAM",
    },
    "lambda_function_vpc_enabled": {
        "cli": (
            "# Add Lambda function to VPC\n"
            "aws lambda update-function-configuration \\\n"
            "  --function-name <FUNCTION> \\\n"
            "  --vpc-config SubnetIds=<SUBNET_IDS>,SecurityGroupIds=<SG_IDS>"
        ),
        "terraform": (
            'resource "aws_lambda_function" "main" {\n'
            '  vpc_config {\n'
            '    subnet_ids         = var.private_subnet_ids\n'
            '    security_group_ids = [aws_security_group.lambda.id]\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "VpcConfig:\n  SubnetIds: [subnet-123]\n  SecurityGroupIds: [sg-123]",
    },
    "opensearch_service_domains_encryption_at_rest_enabled": {
        "cli": (
            "# Create new OpenSearch domain with encryption\n"
            "aws opensearch create-domain \\\n"
            "  --domain-name <NAME> \\\n"
            "  --encryption-at-rest-options Enabled=true,KmsKeyId=<KEY_ID>"
        ),
        "terraform": (
            'resource "aws_opensearch_domain" "main" {\n'
            '  encrypt_at_rest {\n'
            '    enabled    = true\n'
            '    kms_key_id = aws_kms_key.opensearch.arn\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "EncryptionAtRestOptions:\n  Enabled: true",
    },
    "redshift_cluster_encryption": {
        "cli": (
            "# Create encrypted Redshift cluster\n"
            "aws redshift create-cluster \\\n"
            "  --cluster-identifier <CLUSTER> \\\n"
            "  --encrypted \\\n"
            "  --kms-key-id <KMS_KEY>"
        ),
        "terraform": (
            'resource "aws_redshift_cluster" "main" {\n'
            '  encrypted  = true\n'
            '  kms_key_id = aws_kms_key.redshift.arn\n'
            '}'
        ),
        "cloudformation": "Encrypted: true\nKmsKeyId: !Ref RedshiftKey",
    },
    "redshift_cluster_public_access": {
        "cli": (
            "# Make Redshift cluster private\n"
            "aws redshift modify-cluster \\\n"
            "  --cluster-identifier <CLUSTER> \\\n"
            "  --no-publicly-accessible"
        ),
        "terraform": (
            'resource "aws_redshift_cluster" "main" {\n'
            '  publicly_accessible = false\n'
            '}'
        ),
        "cloudformation": "PubliclyAccessible: false",
    },
    "rds_snapshots_public_access": {
        "cli": (
            "# Make RDS snapshot private\n"
            "aws rds modify-db-snapshot-attribute \\\n"
            "  --db-snapshot-identifier <SNAPSHOT> \\\n"
            "  --attribute-name restore \\\n"
            "  --values-to-remove all"
        ),
        "terraform": "# Ensure no aws_db_snapshot public sharing",
        "cloudformation": "# Modify snapshot attributes via console",
    },
    "rds_automated_backups": {
        "cli": (
            "# Enable automated backups\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB> \\\n"
            "  --backup-retention-period 7"
        ),
        "terraform": "backup_retention_period = 7",
        "cloudformation": "BackupRetentionPeriod: 7",
    },
    "s3_account_level_public_access_blocks": {
        "cli": (
            "# Enable account-level S3 public access block\n"
            "aws s3control put-public-access-block \\\n"
            "  --account-id <ACCOUNT_ID> \\\n"
            "  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "terraform": (
            'resource "aws_s3_account_public_access_block" "main" {\n'
            '  block_public_acls       = true\n'
            '  block_public_policy     = true\n'
            '  ignore_public_acls      = true\n'
            '  restrict_public_buckets = true\n'
            '}'
        ),
        "cloudformation": "Type: AWS::S3::AccountPublicAccessBlock",
    },
    "s3_bucket_level_public_access_block": {
        "cli": (
            "# Enable bucket-level public access block\n"
            "aws s3api put-public-access-block \\\n"
            "  --bucket <BUCKET> \\\n"
            "  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "main" {\n'
            '  bucket                  = aws_s3_bucket.main.id\n'
            '  block_public_acls       = true\n'
            '  block_public_policy     = true\n'
            '  ignore_public_acls      = true\n'
            '  restrict_public_buckets = true\n'
            '}'
        ),
        "cloudformation": "Type: AWS::S3::BucketPublicAccessBlock",
    },
    "s3_bucket_mfa_delete": {
        "cli": (
            "# Enable MFA Delete (requires root account MFA)\n"
            "aws s3api put-bucket-versioning \\\n"
            "  --bucket <BUCKET> \\\n"
            "  --versioning-configuration Status=Enabled,MFADelete=Enabled \\\n"
            "  --mfa \"<MFA_SERIAL> <MFA_CODE>\""
        ),
        "terraform": "# MFA delete requires root account credentials",
        "cloudformation": "# MFA delete must be enabled via CLI with root MFA",
    },
    "s3_bucket_no_lifecycle_configuration": {
        "cli": (
            "# Add lifecycle policy to S3 bucket\n"
            "aws s3api put-bucket-lifecycle-configuration \\\n"
            "  --bucket <BUCKET> \\\n"
            "  --lifecycle-configuration '{\"Rules\":[{\"Id\":\"archive-old-objects\",\"Status\":\"Enabled\",\"Transitions\":[{\"Days\":90,\"StorageClass\":\"GLACIER\"}],\"Expiration\":{\"Days\":365}}]}'"
        ),
        "terraform": (
            'resource "aws_s3_bucket_lifecycle_configuration" "main" {\n'
            '  rule {\n'
            '    id     = "archive-old-objects"\n'
            '    status = "Enabled"\n'
            '    transition {\n'
            '      days          = 90\n'
            '      storage_class = "GLACIER"\n'
            '    }\n'
            '    expiration {\n'
            '      days = 365\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Type: AWS::S3::BucketLifecycleConfiguration",
    },
    "s3_bucket_server_side_encryption_enabled": {
        "cli": (
            "# Enable default SSE-S3 encryption\n"
            "aws s3api put-bucket-encryption \\\n"
            "  --bucket <BUCKET> \\\n"
            "  --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
        ),
        "terraform": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "main" {\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            '      sse_algorithm = "AES256"\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "BucketEncryption:\n  ServerSideEncryptionConfiguration:\n    - ServerSideEncryptionByDefault:\n        SSEAlgorithm: AES256",
    },
    "secretsmanager_rotation_enabled": {
        "cli": (
            "# Enable automatic rotation\n"
            "aws secretsmanager rotate-secret \\\n"
            "  --secret-id <SECRET_ID> \\\n"
            "  --rotation-lambda-arn <LAMBDA_ARN> \\\n"
            "  --rotation-rules AutomaticallyAfterDays=30"
        ),
        "terraform": (
            'resource "aws_secretsmanager_secret_rotation" "main" {\n'
            '  rotation_rules {\n'
            '    automatically_after_days = 30\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Type: AWS::SecretsManager::RotationSchedule",
    },
    "secretsmanager_secret_not_used": {
        "cli": (
            "# Delete unused secret\n"
            "aws secretsmanager delete-secret \\\n"
            "  --secret-id <SECRET_ID> \\\n"
            "  --recovery-window-in-days 30"
        ),
        "terraform": "# Remove unused aws_secretsmanager_secret resources",
        "cloudformation": "# Remove unused AWS::SecretsManager::Secret resources",
    },
    "ssm_document_secrets_in_variables": {
        "cli": (
            "# Use SecureString parameters instead of plain variables\n"
            "aws ssm put-parameter \\\n"
            "  --name /app/db-password \\\n"
            "  --type SecureString \\\n"
            "  --value <PASSWORD> \\\n"
            "  --key-id <KMS_KEY>"
        ),
        "terraform": (
            'resource "aws_ssm_parameter" "db_password" {\n'
            '  type   = "SecureString"\n'
            '  key_id = aws_kms_key.ssm.arn\n'
            '}'
        ),
        "cloudformation": "Type: SecureString in AWS::SSM::Parameter",
    },
    "ssm_parameter_encryption": {
        "cli": (
            "# Create encrypted SSM parameter\n"
            "aws ssm put-parameter \\\n"
            "  --name /app/secret \\\n"
            "  --type SecureString \\\n"
            "  --value <VALUE> \\\n"
            "  --key-id <KMS_KEY>"
        ),
        "terraform": (
            'resource "aws_ssm_parameter" "secret" {\n'
            '  type   = "SecureString"\n'
            '  key_id = aws_kms_key.ssm.arn\n'
            '}'
        ),
        "cloudformation": "Type: SecureString",
    },
    "vpc_default_security_group_restricts_all_traffic": {
        "cli": (
            "# Remove all rules from default security group\n"
            "aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[*].GroupId' --output text | \\\n"
            "xargs -I {} aws ec2 revoke-security-group-ingress --group-id {} --ip-permissions '[...]'"
        ),
        "terraform": (
            'resource "aws_default_security_group" "default" {\n'
            '  vpc_id = aws_vpc.main.id\n'
            '  # No ingress or egress rules\n'
            '}'
        ),
        "cloudformation": "# Ensure default SG has no rules",
    },
    "vpc_endpoint_exposed": {
        "cli": (
            "# Restrict VPC endpoint access\n"
            "aws ec2 modify-vpc-endpoint \\\n"
            "  --vpc-endpoint-id <ENDPOINT_ID> \\\n"
            "  --policy-document '{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::<ACCOUNT>:root\"},\"Action\":\"*\",\"Resource\":\"*\"}]}'"
        ),
        "terraform": (
            'resource "aws_vpc_endpoint" "main" {\n'
            '  policy = jsonencode({\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }\n'
            '      Action = "*"\n'
            '      Resource = "*"\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": "PolicyDocument with restricted Principal",
    },
}

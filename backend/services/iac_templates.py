"""
IaC Remediation Templates
Returns AWS CLI / Terraform / CloudFormation fix snippets per check_id.
"""
from typing import Dict

IAC: Dict[str, Dict[str, str]] = {
    "s3_bucket_public_access": {
        "cli": (
            "# Block all public access to S3 bucket\n"
            "aws s3api put-public-access-block \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true\n"
            "\n# Verify configuration\n"
            "aws s3api get-public-access-block --bucket <BUCKET_NAME>"
        ),
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "fix" {\n'
            '  bucket                  = "<BUCKET_NAME>"\n'
            '  block_public_acls       = true\n'
            '  ignore_public_acls      = true\n'
            '  block_public_policy     = true\n'
            '  restrict_public_buckets = true\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\nProperties:\n"
            "  PublicAccessBlockConfiguration:\n"
            "    BlockPublicAcls: true\n"
            "    IgnorePublicAcls: true\n"
            "    BlockPublicPolicy: true\n"
            "    RestrictPublicBuckets: true"
        ),
    },
    "s3_bucket_public_access_block": {
        "cli": (
            "aws s3api put-public-access-block \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "fix" {\n'
            '  bucket                  = "<BUCKET_NAME>"\n'
            '  block_public_acls       = true\n'
            '  ignore_public_acls      = true\n'
            '  block_public_policy     = true\n'
            '  restrict_public_buckets = true\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\nProperties:\n"
            "  PublicAccessBlockConfiguration:\n"
            "    BlockPublicAcls: true\n"
            "    IgnorePublicAcls: true\n"
            "    BlockPublicPolicy: true\n"
            "    RestrictPublicBuckets: true"
        ),
    },
    "iam_root_mfa_enabled": {
        "cli": (
            "# Enable virtual MFA on root — must be done via AWS Console:\n"
            "# IAM → Security credentials → Assign MFA device\n"
            "# Alternatively via CLI (requires root session):\n"
            "aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa \\\n"
            "  --outfile /tmp/root_mfa_qr.png --bootstrap-method QRCodePNG"
        ),
        "terraform": (
            '# Root MFA cannot be managed via Terraform directly.\n'
            '# Use aws_iam_account_password_policy for account-level controls:\n'
            'resource "aws_iam_account_password_policy" "strict" {\n'
            '  require_uppercase_characters   = true\n'
            '  require_lowercase_characters   = true\n'
            '  require_numbers                = true\n'
            '  minimum_password_length        = 14\n'
            '  password_reuse_prevention      = 24\n'
            '  max_password_age               = 90\n'
            '}'
        ),
        "cloudformation": (
            "# Root MFA is enforced via AWS Organizations SCP:\n"
            "Type: AWS::Organizations::Policy\nProperties:\n"
            "  Type: SERVICE_CONTROL_POLICY\n"
            "  Content: |\n"
            "    {\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\n"
            "    \"Action\":\"*\",\"Resource\":\"*\",\n"
            "    \"Condition\":{\"BoolIfExists\":{\"aws:MultiFactorAuthPresent\":\"false\"}}}]}"
        ),
    },
    "ec2_ebs_volume_unattached": {
        "cli": (
            "# List unattached volumes\n"
            "aws ec2 describe-volumes --filters Name=status,Values=available \\\n"
            "  --query 'Volumes[*].{ID:VolumeId,Size:Size,AZ:AvailabilityZone}'\n\n"
            "# Delete a specific volume (IRREVERSIBLE — snapshot first!)\n"
            "aws ec2 create-snapshot --volume-id <VOLUME_ID> --description 'Final backup'\n"
            "aws ec2 delete-volume --volume-id <VOLUME_ID>"
        ),
        "terraform": (
            '# Remove the unattached volume resource from your state:\n'
            '# terraform state rm aws_ebs_volume.<resource_name>\n'
            '# Then remove from .tf file and run terraform apply'
        ),
        "cloudformation": (
            "# Remove the AWS::EC2::Volume resource from your template\n"
            "# and update the stack to delete it."
        ),
    },
    "guardduty_enabled": {
        "cli": (
            "# Enable GuardDuty in current region\n"
            "aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES\n\n"
            "# Enable in ALL regions (loop)\n"
            "for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n"
            "  aws guardduty create-detector --enable --region $region\n"
            "done"
        ),
        "terraform": (
            'resource "aws_guardduty_detector" "main" {\n'
            '  enable                       = true\n'
            '  finding_publishing_frequency = "FIFTEEN_MINUTES"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::GuardDuty::Detector\nProperties:\n"
            "  Enable: true\n"
            "  FindingPublishingFrequency: FIFTEEN_MINUTES"
        ),
    },
    "cloudtrail_enabled": {
        "cli": (
            "aws cloudtrail create-trail \\\n"
            "  --name org-audit-trail \\\n"
            "  --s3-bucket-name <AUDIT-BUCKET> \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation\n"
            "aws cloudtrail start-logging --name org-audit-trail"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  name                          = "org-audit-trail"\n'
            '  s3_bucket_name                = "<AUDIT-BUCKET>"\n'
            '  is_multi_region_trail         = true\n'
            '  enable_log_file_validation    = true\n'
            '  include_global_service_events = true\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::CloudTrail::Trail\nProperties:\n"
            "  TrailName: org-audit-trail\n"
            "  S3BucketName: !Ref AuditBucket\n"
            "  IsMultiRegionTrail: true\n"
            "  EnableLogFileValidation: true\n"
            "  IsLogging: true"
        ),
    },
    "ec2_instance_public_ip": {
        "cli": (
            "# Remove public IP from EC2 instance (requires stop/start)\n"
            "# Step 1: Stop the instance\n"
            "aws ec2 stop-instances --instance-ids <INSTANCE_ID>\n"
            "aws ec2 wait instance-stopped --instance-ids <INSTANCE_ID>\n\n"
            "# Step 2: Modify to remove public IP\n"
            "aws ec2 modify-instance-attribute \\\n"
            "  --instance-id <INSTANCE_ID> \\\n"
            "  --no-associate-public-ip-address\n\n"
            "# Step 3: Start instance\n"
            "aws ec2 start-instances --instance-ids <INSTANCE_ID>"
        ),
        "terraform": (
            'resource "aws_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  associate_public_ip_address = false\n'
            '  subnet_id                   = aws_subnet.private.id\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EC2::Instance\nProperties:\n"
            "  SubnetId: !Ref PrivateSubnet\n"
            "  # Do not set PublicIpAddress property"
        ),
    },
    "kms_cmk_rotation_enabled": {
        "cli": (
            "# Enable automatic key rotation for KMS CMK\n"
            "aws kms enable-key-rotation --key-id <KEY_ID>\n\n"
            "# Verify rotation is enabled\n"
            "aws kms get-key-rotation-status --key-id <KEY_ID>"
        ),
        "terraform": (
            'resource "aws_kms_key" "main" {\n'
            '  description             = "Key with rotation"\n'
            '  enable_key_rotation     = true\n'
            '  deletion_window_in_days = 10\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::KMS::Key\nProperties:\n"
            "  EnableKeyRotation: true\n"
            "  KeyPolicy: !Ref KeyPolicy"
        ),
    },
    "ec2_elastic_ip_unassociated": {
        "cli": (
            "# List unassociated Elastic IPs\n"
            "aws ec2 describe-addresses \\\n"
            "  --query 'Addresses[?AssociationId==null].{IP:PublicIp,AllocId:AllocationId}'\n\n"
            "# Release unassociated EIP\n"
            "aws ec2 release-address --allocation-id <ALLOCATION_ID>"
        ),
        "terraform": (
            '# Remove or comment out the aws_eip resource that is unassociated\n'
            '# resource "aws_eip" "unused" { ... }  <-- delete this block'
        ),
        "cloudformation": (
            "# Remove the AWS::EC2::EIP resource from your template\n"
            "# and run a stack update to release it."
        ),
    },
    "rds_instance_publicly_accessible": {
        "cli": (
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB_INSTANCE_ID> \\\n"
            "  --no-publicly-accessible \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  publicly_accessible = false\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::RDS::DBInstance\nProperties:\n"
            "  PubliclyAccessible: false"
        ),
    },
    "vpc_flow_logs_enabled": {
        "cli": (
            "# Enable VPC Flow Logs to CloudWatch\n"
            "aws ec2 create-flow-logs \\\n"
            "  --resource-type VPC \\\n"
            "  --resource-ids <VPC_ID> \\\n"
            "  --traffic-type ALL \\\n"
            "  --log-destination-type cloud-watch-logs \\\n"
            "  --log-group-name /aws/vpc/flowlogs \\\n"
            "  --deliver-logs-permission-arn <IAM_ROLE_ARN>"
        ),
        "terraform": (
            'resource "aws_flow_log" "main" {\n'
            '  vpc_id          = aws_vpc.main.id\n'
            '  traffic_type    = "ALL"\n'
            '  iam_role_arn    = aws_iam_role.flow_log.arn\n'
            '  log_destination = aws_cloudwatch_log_group.flow_log.arn\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EC2::FlowLog\nProperties:\n"
            "  ResourceType: VPC\n"
            "  ResourceIds: [!Ref VPC]\n"
            "  TrafficType: ALL\n"
            "  LogDestinationType: cloud-watch-logs"
        ),
    },
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
        "cli": (
            "# Remove public SSH access (0.0.0.0/0) from security group\n"
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id <SG_ID> \\\n"
            "  --protocol tcp \\\n"
            "  --port 22 \\\n"
            "  --cidr 0.0.0.0/0\n\n"
            "# Add restricted SSH access from your VPN/office IP\n"
            "aws ec2 authorize-security-group-ingress \\\n"
            "  --group-id <SG_ID> \\\n"
            "  --protocol tcp \\\n"
            "  --port 22 \\\n"
            "  --cidr <YOUR_IP>/32"
        ),
        "terraform": (
            'resource "aws_security_group_rule" "ssh_restricted" {\n'
            '  type              = "ingress"\n'
            '  from_port         = 22\n'
            '  to_port           = 22\n'
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["<YOUR_IP>/32"]  # Replace with your IP\n'
            '  security_group_id = aws_security_group.main.id\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EC2::SecurityGroupIngress\nProperties:\n"
            "  GroupId: !Ref SecurityGroup\n"
            "  IpProtocol: tcp\n"
            "  FromPort: 22\n"
            "  ToPort: 22\n"
            "  CidrIp: <YOUR_IP>/32"
        ),
    },
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": {
        "cli": (
            "# Remove public RDP access (0.0.0.0/0) from security group\n"
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id <SG_ID> \\\n"
            "  --protocol tcp \\\n"
            "  --port 3389 \\\n"
            "  --cidr 0.0.0.0/0\n\n"
            "# Add restricted RDP access\n"
            "aws ec2 authorize-security-group-ingress \\\n"
            "  --group-id <SG_ID> \\\n"
            "  --protocol tcp \\\n"
            "  --port 3389 \\\n"
            "  --cidr <YOUR_IP>/32"
        ),
        "terraform": (
            'resource "aws_security_group_rule" "rdp_restricted" {\n'
            '  type              = "ingress"\n'
            '  from_port         = 3389\n'
            '  to_port           = 3389\n'
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["<YOUR_IP>/32"]\n'
            '  security_group_id = aws_security_group.main.id\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EC2::SecurityGroupIngress\nProperties:\n"
            "  IpProtocol: tcp\n"
            "  FromPort: 3389\n"
            "  ToPort: 3389\n"
            "  CidrIp: <YOUR_IP>/32"
        ),
    },
    "s3_bucket_versioning_enabled": {
        "cli": (
            "# Enable S3 bucket versioning\n"
            "aws s3api put-bucket-versioning \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --versioning-configuration Status=Enabled\n\n"
            "# Verify versioning status\n"
            "aws s3api get-bucket-versioning --bucket <BUCKET_NAME>"
        ),
        "terraform": (
            'resource "aws_s3_bucket_versioning" "main" {\n'
            '  bucket = aws_s3_bucket.main.id\n'
            '  versioning_configuration {\n'
            '    status = "Enabled"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\nProperties:\n"
            "  VersioningConfiguration:\n"
            "    Status: Enabled"
        ),
    },
    "s3_bucket_logging_enabled": {
        "cli": (
            "# Enable S3 server access logging\n"
            "aws s3api put-bucket-logging \\\n"
            "  --bucket <SOURCE_BUCKET> \\\n"
            "  --bucket-logging-status \"{\\\"LoggingEnabled\\\":{\\\"TargetBucket\\\":\\\"<LOG_BUCKET>\\\",\\\"TargetPrefix\\\":\\\"logs/\\\"}}\""
        ),
        "terraform": (
            'resource "aws_s3_bucket_logging" "main" {\n'
            '  bucket        = aws_s3_bucket.main.id\n'
            '  target_bucket = aws_s3_bucket.log_bucket.id\n'
            '  target_prefix = "logs/"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\nProperties:\n"
            "  LoggingConfiguration:\n"
            "    DestinationBucketName: !Ref LogBucket\n"
            "    LogFilePrefix: logs/"
        ),
    },
    "s3_bucket_encryption": {
        "cli": (
            "# Enable default encryption on S3 bucket\n"
            "aws s3api put-bucket-encryption \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --server-side-encryption-configuration \"{\\\"Rules\\\":[{\\\"ApplyServerSideEncryptionByDefault\\\":{\\\"SSEAlgorithm\\\":\\\"AES256\\\"}}]}\""
        ),
        "terraform": (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "main" {\n'
            '  bucket = aws_s3_bucket.main.id\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            '      sse_algorithm = "AES256"\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\nProperties:\n"
            "  BucketEncryption:\n"
            "    ServerSideEncryptionConfiguration:\n"
            "      - ServerSideEncryptionByDefault:\n"
            "          SSEAlgorithm: AES256"
        ),
    },
    "s3_bucket_secure_transport": {
        "cli": (
            "# Enforce HTTPS-only access via bucket policy\n"
            "aws s3api put-bucket-policy \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --policy '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::<BUCKET>/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}'"
        ),
        "terraform": (
            'data "aws_iam_policy_document" "https_only" {\n'
            '  statement {\n'
            '    effect = "Deny"\n'
            '    principals { type = "*"; identifiers = ["*"] }\n'
            '    actions = ["s3:*"]\n'
            '    resources = ["${aws_s3_bucket.main.arn}/*"]\n'
            '    condition {\n'
            '      test     = "Bool"\n'
            '      variable = "aws:SecureTransport"\n'
            '      values   = ["false"]\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::BucketPolicy\nProperties:\n"
            "  PolicyDocument:\n"
            "    Statement:\n"
            "      - Effect: Deny\n"
            "        Principal: '*'\n"
            "        Action: s3:*\n"
            "        Condition:\n"
            "          Bool:\n"
            "            aws:SecureTransport: false"
        ),
    },
    "iam_user_mfa_enabled": {
        "cli": (
            "# Enable MFA for IAM user\n"
            "# Step 1: Create virtual MFA device\n"
            "aws iam create-virtual-mfa-device \\\n"
            "  --virtual-mfa-device-name <USERNAME>-mfa \\\n"
            "  --outfile /tmp/qr-code.png \\\n"
            "  --bootstrap-method QRCodePNG\n\n"
            "# Step 2: User scans QR code and provides two consecutive codes\n"
            "aws iam enable-mfa-device \\\n"
            "  --user-name <USERNAME> \\\n"
            "  --serial-number <MFA_DEVICE_ARN> \\\n"
            "  --authentication-code1 <CODE1> \\\n"
            "  --authentication-code2 <CODE2>"
        ),
        "terraform": (
            '# MFA devices must be configured manually by users\n'
            '# Enforce MFA via IAM policy:\n'
            'resource "aws_iam_policy" "enforce_mfa" {\n'
            '  name = "EnforceMFA"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Deny"\n'
            '      Action = "*"\n'
            '      Resource = "*"\n'
            '      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent": "false" } }\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "# MFA is user-specific and managed via console or CLI\n"
            "# Enforce via IAM policy"
        ),
    },
    "cloudwatch_log_group_retention_policy_specific_days_enabled": {
        "cli": (
            "# Set CloudWatch log retention to 90 days\n"
            "aws logs put-retention-policy \\\n"
            "  --log-group-name <LOG_GROUP_NAME> \\\n"
            "  --retention-in-days 90"
        ),
        "terraform": (
            'resource "aws_cloudwatch_log_group" "main" {\n'
            '  name              = "/aws/lambda/my-function"\n'
            '  retention_in_days = 90\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Logs::LogGroup\nProperties:\n"
            "  LogGroupName: /aws/lambda/my-function\n"
            "  RetentionInDays: 90"
        ),
    },
    "rds_instance_encryption": {
        "cli": (
            "# RDS encryption must be enabled at creation time\n"
            "# Create encrypted snapshot and restore to new instance:\n"
            "aws rds create-db-snapshot \\\n"
            "  --db-instance-identifier <OLD_INSTANCE> \\\n"
            "  --db-snapshot-identifier <SNAPSHOT_NAME>\n\n"
            "aws rds copy-db-snapshot \\\n"
            "  --source-db-snapshot-identifier <SNAPSHOT_NAME> \\\n"
            "  --target-db-snapshot-identifier <ENCRYPTED_SNAPSHOT> \\\n"
            "  --kms-key-id <KMS_KEY_ID>\n\n"
            "aws rds restore-db-instance-from-db-snapshot \\\n"
            "  --db-instance-identifier <NEW_INSTANCE> \\\n"
            "  --db-snapshot-identifier <ENCRYPTED_SNAPSHOT>"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  storage_encrypted = true\n'
            '  kms_key_id        = aws_kms_key.db.arn\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::RDS::DBInstance\nProperties:\n"
            "  StorageEncrypted: true\n"
            "  KmsKeyId: !Ref KMSKey"
        ),
    },
    "ec2_ebs_volume_encryption": {
        "cli": (
            "# Enable EBS encryption by default in region\n"
            "aws ec2 enable-ebs-encryption-by-default --region <REGION>\n\n"
            "# Verify encryption is enabled\n"
            "aws ec2 get-ebs-encryption-by-default --region <REGION>"
        ),
        "terraform": (
            'resource "aws_ebs_encryption_by_default" "main" {\n'
            '  enabled = true\n'
            '}'
        ),
        "cloudformation": (
            "# EBS encryption by default is a region-level setting\n"
            "# Must be configured via console or CLI"
        ),
    },
    "lambda_function_restrict_public_access": {
        "cli": (
            "# Remove public access from Lambda function\n"
            "aws lambda remove-permission \\\n"
            "  --function-name <FUNCTION_NAME> \\\n"
            "  --statement-id AllowPublicAccess\n\n"
            "# List current permissions\n"
            "aws lambda get-policy --function-name <FUNCTION_NAME>"
        ),
        "terraform": (
            '# Ensure no aws_lambda_permission with Principal = "*"\n'
            'resource "aws_lambda_function" "main" {\n'
            '  # ... existing config ...\n'
            '  # Do NOT add public permission\n'
            '}'
        ),
        "cloudformation": (
            "# Remove any AWS::Lambda::Permission with Principal: '*'"
        ),
    },
    
    # Additional 20+ common Prowler checks
    "iam_password_policy_minimum_length_14": {
        "cli": (
            "# Update IAM password policy to require minimum 14 characters\n"
            "aws iam update-account-password-policy \\\n"
            "  --minimum-password-length 14 \\\n"
            "  --require-uppercase-characters \\\n"
            "  --require-lowercase-characters \\\n"
            "  --require-numbers \\\n"
            "  --require-symbols \\\n"
            "  --max-password-age 90 \\\n"
            "  --password-reuse-prevention 24"
        ),
        "terraform": (
            'resource "aws_iam_account_password_policy" "strict" {\n'
            '  minimum_password_length        = 14\n'
            '  require_uppercase_characters   = true\n'
            '  require_lowercase_characters   = true\n'
            '  require_numbers                = true\n'
            '  require_symbols                = true\n'
            '  max_password_age               = 90\n'
            '  password_reuse_prevention      = 24\n'
            '}'
        ),
        "cloudformation": "# IAM password policy is account-level, configured via console or CLI",
    },
    "iam_access_keys_rotated": {
        "cli": (
            "# List access keys older than 90 days\n"
            "aws iam list-access-keys --user-name <USERNAME>\n\n"
            "# Delete old access key\n"
            "aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>\n\n"
            "# Create new access key\n"
            "aws iam create-access-key --user-name <USERNAME>"
        ),
        "terraform": "# Access key rotation should be automated via CI/CD or rotation Lambda",
        "cloudformation": "# Use AWS Secrets Manager for automatic credential rotation",
    },
    "iam_policy_no_full_access_to_services": {
        "cli": (
            "# Remove overly permissive policies\n"
            "aws iam detach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
            "# Attach least-privilege policy instead\n"
            "aws iam attach-user-policy --user-name <USER> --policy-arn <LEAST_PRIVILEGE_POLICY_ARN>"
        ),
        "terraform": (
            '# Use least-privilege policies\n'
            'resource "aws_iam_user_policy_attachment" "limited" {\n'
            '  user       = aws_iam_user.main.name\n'
            '  policy_arn = aws_iam_policy.least_privilege.arn\n'
            '}'
        ),
        "cloudformation": "# Attach specific policies, avoid AdministratorAccess",
    },
    "securityhub_enabled": {
        "cli": (
            "# Enable AWS Security Hub\n"
            "aws securityhub enable-security-hub --region <REGION>\n\n"
            "# Enable CIS AWS Foundations Benchmark standard\n"
            "aws securityhub batch-enable-standards \\\n"
            "  --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
        ),
        "terraform": (
            'resource "aws_securityhub_account" "main" {}\n'
            '\n'
            'resource "aws_securityhub_standards_subscription" "cis" {\n'
            '  standards_arn = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0"\n'
            '}'
        ),
        "cloudformation": "Type: AWS::SecurityHub::Hub",
    },
    "config_recorder_all_regions_enabled": {
        "cli": (
            "# Enable AWS Config in all regions\n"
            "for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n"
            "  aws configservice put-configuration-recorder \\\n"
            "    --configuration-recorder name=default,roleARN=<CONFIG_ROLE_ARN> \\\n"
            "    --recording-group allSupported=true,includeGlobalResourceTypes=true \\\n"
            "    --region $region\n"
            "  aws configservice start-configuration-recorder --configuration-recorder-name default --region $region\n"
            "done"
        ),
        "terraform": (
            'resource "aws_config_configuration_recorder" "main" {\n'
            '  name     = "default"\n'
            '  role_arn = aws_iam_role.config.arn\n'
            '  recording_group {\n'
            '    all_supported                 = true\n'
            '    include_global_resource_types = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "Type: AWS::Config::ConfigurationRecorder",
    },
    "cloudtrail_multi_region_enabled": {
        "cli": (
            "# Create multi-region CloudTrail\n"
            "aws cloudtrail create-trail \\\n"
            "  --name org-audit-trail \\\n"
            "  --s3-bucket-name <AUDIT_BUCKET> \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation\n\n"
            "aws cloudtrail start-logging --name org-audit-trail"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  name                          = "org-audit-trail"\n'
            '  s3_bucket_name                = aws_s3_bucket.audit.id\n'
            '  is_multi_region_trail         = true\n'
            '  enable_log_file_validation    = true\n'
            '  include_global_service_events = true\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::CloudTrail::Trail\nProperties:\n"
            "  IsMultiRegionTrail: true\n"
            "  EnableLogFileValidation: true"
        ),
    },
    "cloudtrail_log_file_validation_enabled": {
        "cli": (
            "# Enable log file validation on existing trail\n"
            "aws cloudtrail update-trail \\\n"
            "  --name <TRAIL_NAME> \\\n"
            "  --enable-log-file-validation"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  # ... existing config ...\n'
            '  enable_log_file_validation = true\n'
            '}'
        ),
        "cloudformation": "EnableLogFileValidation: true",
    },
    "elbv2_logging_enabled": {
        "cli": (
            "# Enable ALB/NLB access logging\n"
            "aws elbv2 modify-load-balancer-attributes \\\n"
            "  --load-balancer-arn <ALB_ARN> \\\n"
            "  --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<LOG_BUCKET>"
        ),
        "terraform": (
            'resource "aws_lb" "main" {\n'
            '  # ... existing config ...\n'
            '  access_logs {\n'
            '    bucket  = aws_s3_bucket.lb_logs.bucket\n'
            '    enabled = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ElasticLoadBalancingV2::LoadBalancer\nProperties:\n"
            "  LoadBalancerAttributes:\n"
            "    - Key: access_logs.s3.enabled\n"
            "      Value: true"
        ),
    },
    "elbv2_deletion_protection": {
        "cli": (
            "# Enable deletion protection on ALB/NLB\n"
            "aws elbv2 modify-load-balancer-attributes \\\n"
            "  --load-balancer-arn <ALB_ARN> \\\n"
            "  --attributes Key=deletion_protection.enabled,Value=true"
        ),
        "terraform": (
            'resource "aws_lb" "main" {\n'
            '  # ... existing config ...\n'
            '  enable_deletion_protection = true\n'
            '}'
        ),
        "cloudformation": "# Set LoadBalancerAttribute: deletion_protection.enabled=true",
    },
    "rds_instance_backup_enabled": {
        "cli": (
            "# Enable automated backups on RDS instance\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB_INSTANCE> \\\n"
            "  --backup-retention-period 7 \\\n"
            "  --preferred-backup-window \"03:00-04:00\" \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  backup_retention_period = 7\n'
            '  backup_window          = "03:00-04:00"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::RDS::DBInstance\nProperties:\n"
            "  BackupRetentionPeriod: 7\n"
            "  PreferredBackupWindow: 03:00-04:00"
        ),
    },
    "rds_instance_multi_az": {
        "cli": (
            "# Enable Multi-AZ on RDS instance\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB_INSTANCE> \\\n"
            "  --multi-az \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  multi_az = true\n'
            '}'
        ),
        "cloudformation": "MultiAZ: true",
    },
    "rds_instance_deletion_protection": {
        "cli": (
            "# Enable deletion protection on RDS instance\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB_INSTANCE> \\\n"
            "  --deletion-protection \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  deletion_protection = true\n'
            '}'
        ),
        "cloudformation": "DeletionProtection: true",
    },
    "ec2_instance_imdsv2": {
        "cli": (
            "# Enforce IMDSv2 on EC2 instance\n"
            "aws ec2 modify-instance-metadata-options \\\n"
            "  --instance-id <INSTANCE_ID> \\\n"
            "  --http-tokens required \\\n"
            "  --http-put-response-hop-limit 1"
        ),
        "terraform": (
            'resource "aws_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  metadata_options {\n'
            '    http_tokens = "required"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "MetadataOptions:\n"
            "  HttpTokens: required\n"
            "  HttpPutResponseHopLimit: 1"
        ),
    },
    "ec2_securitygroup_default_restrict_traffic": {
        "cli": (
            "# Remove all rules from default security group\n"
            "aws ec2 revoke-security-group-ingress --group-id <DEFAULT_SG_ID> --ip-permissions '[...]'\n"
            "aws ec2 revoke-security-group-egress --group-id <DEFAULT_SG_ID> --ip-permissions '[...]'"
        ),
        "terraform": (
            '# Ensure default security group has no rules\n'
            'resource "aws_default_security_group" "default" {\n'
            '  vpc_id = aws_vpc.main.id\n'
            '  # No ingress or egress rules\n'
            '}'
        ),
        "cloudformation": "# Manually remove rules from default SG via console",
    },
    "vpc_network_acl_unrestricted": {
        "cli": (
            "# Remove overly permissive NACL rules\n"
            "aws ec2 delete-network-acl-entry --network-acl-id <NACL_ID> --rule-number 100 --ingress\n\n"
            "# Add restrictive rule\n"
            "aws ec2 create-network-acl-entry \\\n"
            "  --network-acl-id <NACL_ID> \\\n"
            "  --rule-number 100 \\\n"
            "  --protocol tcp \\\n"
            "  --port-range From=443,To=443 \\\n"
            "  --cidr-block 10.0.0.0/8 \\\n"
            "  --rule-action allow \\\n"
            "  --ingress"
        ),
        "terraform": (
            'resource "aws_network_acl_rule" "restricted" {\n'
            '  network_acl_id = aws_network_acl.main.id\n'
            '  rule_number    = 100\n'
            '  protocol       = "tcp"\n'
            '  from_port      = 443\n'
            '  to_port        = 443\n'
            '  cidr_block     = "10.0.0.0/8"\n'
            '  rule_action    = "allow"\n'
            '}'
        ),
        "cloudformation": "# Configure restrictive NACL rules via NetworkAclEntry resources",
    },
    "eks_cluster_logging_enabled": {
        "cli": (
            "# Enable EKS control plane logging\n"
            "aws eks update-cluster-config \\\n"
            "  --name <CLUSTER_NAME> \\\n"
            "  --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'"
        ),
        "terraform": (
            'resource "aws_eks_cluster" "main" {\n'
            '  # ... existing config ...\n'
            '  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EKS::Cluster\nProperties:\n"
            "  Logging:\n"
            "    ClusterLogging:\n"
            "      EnabledTypes:\n"
            "        - Type: api\n"
            "        - Type: audit"
        ),
    },
    "eks_endpoints_not_publicly_accessible": {
        "cli": (
            "# Disable public endpoint access on EKS cluster\n"
            "aws eks update-cluster-config \\\n"
            "  --name <CLUSTER_NAME> \\\n"
            "  --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true"
        ),
        "terraform": (
            'resource "aws_eks_cluster" "main" {\n'
            '  # ... existing config ...\n'
            '  vpc_config {\n'
            '    endpoint_public_access  = false\n'
            '    endpoint_private_access = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "ResourcesVpcConfig:\n"
            "  EndpointPublicAccess: false\n"
            "  EndpointPrivateAccess: true"
        ),
    },
    "ecr_repositories_scan_images_on_push_enabled": {
        "cli": (
            "# Enable image scanning on ECR repository\n"
            "aws ecr put-image-scanning-configuration \\\n"
            "  --repository-name <REPO_NAME> \\\n"
            "  --image-scanning-configuration scanOnPush=true"
        ),
        "terraform": (
            'resource "aws_ecr_repository" "main" {\n'
            '  name = "my-app"\n'
            '  image_scanning_configuration {\n'
            '    scan_on_push = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ECR::Repository\nProperties:\n"
            "  ImageScanningConfiguration:\n"
            "    ScanOnPush: true"
        ),
    },
    "ecr_repositories_not_publicly_accessible": {
        "cli": (
            "# Remove public access from ECR repository\n"
            "aws ecr delete-repository-policy --repository-name <REPO_NAME>\n\n"
            "# Set private policy\n"
            "aws ecr set-repository-policy \\\n"
            "  --repository-name <REPO_NAME> \\\n"
            "  --policy-text '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::<ACCOUNT>:root\"},\"Action\":[\"ecr:*\"]}]}'"
        ),
        "terraform": (
            'resource "aws_ecr_repository_policy" "private" {\n'
            '  repository = aws_ecr_repository.main.name\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }\n'
            '      Action = ["ecr:*"]\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": "# Configure RepositoryPolicyText to restrict access to account only",
    },
    "lambda_function_url_cors_policy": {
        "cli": (
            "# Configure CORS on Lambda function URL\n"
            "aws lambda update-function-url-config \\\n"
            "  --function-name <FUNCTION_NAME> \\\n"
            "  --cors '{\"AllowOrigins\":[\"https://example.com\"],\"AllowMethods\":[\"GET\",\"POST\"],\"MaxAge\":300}'"
        ),
        "terraform": (
            'resource "aws_lambda_function_url" "main" {\n'
            '  function_name      = aws_lambda_function.main.function_name\n'
            '  authorization_type = "AWS_IAM"\n'
            '  cors {\n'
            '    allow_origins = ["https://example.com"]\n'
            '    allow_methods = ["GET", "POST"]\n'
            '    max_age       = 300\n'
            '  }\n'
            '}'
        ),
        "cloudformation": "# Configure Cors property in AWS::Lambda::Url resource",
    },
    "secretsmanager_automatic_rotation_enabled": {
        "cli": (
            "# Enable automatic rotation on secret\n"
            "aws secretsmanager rotate-secret \\\n"
            "  --secret-id <SECRET_ID> \\\n"
            "  --rotation-lambda-arn <ROTATION_FUNCTION_ARN> \\\n"
            "  --rotation-rules AutomaticallyAfterDays=30"
        ),
        "terraform": (
            'resource "aws_secretsmanager_secret_rotation" "main" {\n'
            '  secret_id           = aws_secretsmanager_secret.main.id\n'
            '  rotation_lambda_arn = aws_lambda_function.rotation.arn\n'
            '  rotation_rules {\n'
            '    automatically_after_days = 30\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SecretsManager::RotationSchedule\nProperties:\n"
            "  RotationLambdaARN: !GetAtt RotationFunction.Arn\n"
            "  RotationRules:\n"
            "    AutomaticallyAfterDays: 30"
        ),
    },
    "dynamodb_table_encrypted_with_kms": {
        "cli": (
            "# DynamoDB encryption must be enabled at table creation\n"
            "# Create new table with KMS encryption\n"
            "aws dynamodb create-table \\\n"
            "  --table-name <TABLE_NAME> \\\n"
            "  --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<KMS_KEY_ARN> \\\n"
            "  --attribute-definitions AttributeName=id,AttributeType=S \\\n"
            "  --key-schema AttributeName=id,KeyType=HASH \\\n"
            "  --billing-mode PAY_PER_REQUEST"
        ),
        "terraform": (
            'resource "aws_dynamodb_table" "main" {\n'
            '  name         = "my-table"\n'
            '  billing_mode = "PAY_PER_REQUEST"\n'
            '  hash_key     = "id"\n'
            '  server_side_encryption {\n'
            '    enabled     = true\n'
            '    kms_key_arn = aws_kms_key.dynamodb.arn\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::DynamoDB::Table\nProperties:\n"
            "  SSESpecification:\n"
            "    SSEEnabled: true\n"
            "    SSEType: KMS\n"
            "    KMSMasterKeyId: !Ref KMSKey"
        ),
    },
    "apigateway_restapi_logging_enabled": {
        "cli": (
            "# Enable CloudWatch logging for API Gateway stage\n"
            "aws apigateway update-stage \\\n"
            "  --rest-api-id <API_ID> \\\n"
            "  --stage-name <STAGE_NAME> \\\n"
            "  --patch-operations op=replace,path=/*/*/logging/loglevel,value=INFO"
        ),
        "terraform": (
            'resource "aws_api_gateway_stage" "main" {\n'
            '  deployment_id = aws_api_gateway_deployment.main.id\n'
            '  rest_api_id   = aws_api_gateway_rest_api.main.id\n'
            '  stage_name    = "prod"\n'
            '  access_log_settings {\n'
            '    destination_arn = aws_cloudwatch_log_group.api.arn\n'
            '    format         = "$requestId"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ApiGateway::Stage\nProperties:\n"
            "  AccessLogSetting:\n"
            "    DestinationArn: !GetAtt ApiLogGroup.Arn"
        ),
    },
    "backup_vaults_encrypted": {
        "cli": (
            "# Create encrypted backup vault\n"
            "aws backup create-backup-vault \\\n"
            "  --backup-vault-name <VAULT_NAME> \\\n"
            "  --encryption-key-arn <KMS_KEY_ARN>"
        ),
        "terraform": (
            'resource "aws_backup_vault" "main" {\n'
            '  name        = "critical-backups"\n'
            '  kms_key_arn = aws_kms_key.backup.arn\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Backup::BackupVault\nProperties:\n"
            "  EncryptionKeyArn: !GetAtt BackupKey.Arn"
        ),
    },
}

# Import additional CLI batches (relative imports within services package)
try:
    from .iac_batch_1 import IAC_BATCH_1
    from .iac_batch_2 import IAC_BATCH_2
    from .iac_batch_3 import IAC_BATCH_3
    from .iac_batch_4 import IAC_BATCH_4
    from .iac_batch_5 import IAC_BATCH_5
    # Merge all batches into main IAC dictionary
    IAC.update(IAC_BATCH_1)
    IAC.update(IAC_BATCH_2)
    IAC.update(IAC_BATCH_3)
    IAC.update(IAC_BATCH_4)
    IAC.update(IAC_BATCH_5)
    print(f"[IAC Templates] Loaded {len(IAC)} total remediation templates")
except ImportError as e:
    # If relative imports fail, batches not available
    print(f"[IAC Templates] Warning: Could not import all batches: {e}")
    pass

_DEFAULT = {
    "cli":            "# Refer to AWS documentation for CLI remediation steps for this check.",
    "terraform":      "# Refer to the Terraform AWS provider docs for this resource.",
    "cloudformation": "# Refer to AWS CloudFormation resource documentation.",
}


def get_iac(check_id: str, fmt: str) -> str:
    """Return IaC snippet for a given check_id and format (cli/terraform/cloudformation)."""
    entry = IAC.get(check_id, _DEFAULT)
    return entry.get(fmt, _DEFAULT[fmt])


def get_all_formats(check_id: str) -> Dict[str, str]:
    return {
        "cli":            get_iac(check_id, "cli"),
        "terraform":      get_iac(check_id, "terraform"),
        "cloudformation": get_iac(check_id, "cloudformation"),
    }

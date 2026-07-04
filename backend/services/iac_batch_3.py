"""
IAC_BATCH_3: Additional Infrastructure as Code Templates
Extends IAC dictionary with remediation templates for newer Prowler checks
Each entry includes AWS CLI, Terraform, and CloudFormation remediation code
"""

IAC_BATCH_3 = {
    "iam_no_root_access_key": {
        "cli": (
            "# List all access keys for root account\n"
            "aws iam list-access-keys --user-name root\n\n"
            "# Delete root access key (CRITICAL - have MFA enabled first!)\n"
            "aws iam delete-access-key --access-key-id <ACCESS_KEY_ID> --user-name root\n\n"
            "# Verify deletion\n"
            "aws iam list-access-keys --user-name root"
        ),
        "terraform": (
            "# Root account access keys cannot be managed via Terraform\n"
            "# Enforce via AWS Organizations SCP:\n"
            'resource "aws_organizations_policy" "deny_root_access_keys" {\n'
            '  name        = "DenyRootAccessKeys"\n'
            '  type        = "SERVICE_CONTROL_POLICY"\n'
            '  content = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect    = "Deny"\n'
            '      Action    = ["iam:CreateAccessKey", "iam:UpdateAccessKey"]\n'
            '      Resource  = "arn:aws:iam::*:root"\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "# Root access keys cannot be managed via CloudFormation\n"
            "# Use AWS Organizations SCP (Type: AWS::Organizations::Policy)"
        ),
    },
    
    "iam_support_role_exists": {
        "cli": (
            "# Create IAM role for AWS Support access\n"
            "aws iam create-role \\\n"
            "  --role-name AWSSupportRole \\\n"
            "  --assume-role-policy-document file://trust-policy.json\n\n"
            "# Attach AWS managed policy\n"
            "aws iam attach-role-policy \\\n"
            "  --role-name AWSSupportRole \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess\n\n"
            "# Assign to user or group\n"
            "aws iam add-user-to-group --user-name <USERNAME> --group-name SupportTeam"
        ),
        "terraform": (
            'resource "aws_iam_role" "support" {\n'
            '  name = "AWSSupportRole"\n'
            '  assume_role_policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Principal = { Service = "support.amazonaws.com" }\n'
            '      Action = "sts:AssumeRole"\n'
            '    }]\n'
            '  })\n'
            '}\n\n'
            'resource "aws_iam_role_policy_attachment" "support" {\n'
            '  role       = aws_iam_role.support.name\n'
            '  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::IAM::Role\n"
            "Properties:\n"
            "  RoleName: AWSSupportRole\n"
            "  AssumeRolePolicyDocument:\n"
            "    Version: '2012-10-17'\n"
            "    Statement:\n"
            "      - Effect: Allow\n"
            "        Principal:\n"
            "          Service: support.amazonaws.com\n"
            "        Action: sts:AssumeRole\n"
            "  ManagedPolicyArns:\n"
            "    - arn:aws:iam::aws:policy/AWSSupportAccess"
        ),
    },
    
    "s3_bucket_object_lock_enabled": {
        "cli": (
            "# Enable Object Lock on S3 bucket (must be enabled at bucket creation)\n"
            "aws s3api create-bucket \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --object-lock-enabled-for-bucket \\\n"
            "  --region <REGION>\n\n"
            "# Configure default retention\n"
            "aws s3api put-object-lock-configuration \\\n"
            "  --bucket <BUCKET_NAME> \\\n"
            "  --object-lock-configuration '{\n"
            "    \"ObjectLockEnabled\": \"Enabled\",\n"
            "    \"Rule\": {\n"
            "      \"DefaultRetention\": {\n"
            "        \"Mode\": \"GOVERNANCE\",\n"
            "        \"Days\": 30\n"
            "      }\n"
            "    }\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_s3_bucket" "protected" {\n'
            '  bucket              = "my-protected-bucket"\n'
            '  object_lock_enabled = true\n'
            '}\n\n'
            'resource "aws_s3_bucket_object_lock_configuration" "main" {\n'
            '  bucket = aws_s3_bucket.protected.id\n'
            '  rule {\n'
            '    default_retention {\n'
            '      mode = "GOVERNANCE"\n'
            '      days = 30\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::S3::Bucket\n"
            "Properties:\n"
            "  ObjectLockEnabled: true\n"
            "  ObjectLockConfiguration:\n"
            "    ObjectLockEnabled: Enabled\n"
            "    Rule:\n"
            "      DefaultRetention:\n"
            "        Mode: GOVERNANCE\n"
            "        Days: 30"
        ),
    },
    
    "ec2_instance_managed_by_ssm": {
        "cli": (
            "# Install SSM agent (if not pre-installed on Amazon Linux 2)\n"
            "# For existing instances, attach IAM role first:\n"
            "aws iam create-role \\\n"
            "  --role-name SSMManagedRole \\\n"
            "  --assume-role-policy-document file://trust-policy.json\n\n"
            "aws iam attach-role-policy \\\n"
            "  --role-name SSMManagedRole \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore\n\n"
            "# Attach role to instance\n"
            "aws ec2 associate-iam-instance-profile \\\n"
            "  --instance-id <INSTANCE_ID> \\\n"
            "  --iam-instance-profile Name=SSMManagedRole"
        ),
        "terraform": (
            'resource "aws_iam_role" "ssm_managed" {\n'
            '  name = "SSMManagedRole"\n'
            '  assume_role_policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect    = "Allow"\n'
            '      Principal = { Service = "ec2.amazonaws.com" }\n'
            '      Action    = "sts:AssumeRole"\n'
            '    }]\n'
            '  })\n'
            '}\n\n'
            'resource "aws_iam_role_policy_attachment" "ssm" {\n'
            '  role       = aws_iam_role.ssm_managed.name\n'
            '  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"\n'
            '}\n\n'
            'resource "aws_iam_instance_profile" "ssm" {\n'
            '  name = "SSMManagedProfile"\n'
            '  role = aws_iam_role.ssm_managed.name\n'
            '}\n\n'
            'resource "aws_instance" "main" {\n'
            '  # ... other config ...\n'
            '  iam_instance_profile = aws_iam_instance_profile.ssm.name\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::IAM::Role\n"
            "Properties:\n"
            "  ManagedPolicyArns:\n"
            "    - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore\n"
            "  AssumeRolePolicyDocument:\n"
            "    Version: '2012-10-17'\n"
            "    Statement:\n"
            "      - Effect: Allow\n"
            "        Principal:\n"
            "          Service: ec2.amazonaws.com\n"
            "        Action: sts:AssumeRole"
        ),
    },
    
    "rds_instance_iam_authentication_enabled": {
        "cli": (
            "# Enable IAM database authentication\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <DB_INSTANCE_ID> \\\n"
            "  --enable-iam-database-authentication \\\n"
            "  --apply-immediately\n\n"
            "# Generate authentication token for connection\n"
            "aws rds generate-db-auth-token \\\n"
            "  --hostname <DB_ENDPOINT> \\\n"
            "  --port 3306 \\\n"
            "  --username <DB_USER> \\\n"
            "  --region <REGION>"
        ),
        "terraform": (
            'resource "aws_db_instance" "main" {\n'
            '  # ... existing config ...\n'
            '  iam_database_authentication_enabled = true\n'
            '}\n\n'
            '# Grant IAM user/role RDS connect permission\n'
            'resource "aws_iam_policy" "rds_connect" {\n'
            '  name = "RDSConnectPolicy"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect   = "Allow"\n'
            '      Action   = "rds-db:connect"\n'
            '      Resource = "arn:aws:rds-db:${var.region}:${var.account_id}:dbuser:*/${var.db_user}"\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::RDS::DBInstance\n"
            "Properties:\n"
            "  EnableIAMDatabaseAuthentication: true"
        ),
    },
    
    "lambda_function_using_supported_runtimes": {
        "cli": (
            "# Update Lambda function runtime\n"
            "aws lambda update-function-configuration \\\n"
            "  --function-name <FUNCTION_NAME> \\\n"
            "  --runtime python3.12\n\n"
            "# List functions with deprecated runtimes\n"
            "aws lambda list-functions \\\n"
            "  --query 'Functions[?Runtime==`python3.7`].[FunctionName,Runtime]'"
        ),
        "terraform": (
            'resource "aws_lambda_function" "main" {\n'
            '  # ... existing config ...\n'
            '  runtime = "python3.12"  # Use latest supported runtime\n'
            '  # Other supported runtimes: nodejs20.x, java17, dotnet8, go1.x, ruby3.2\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Lambda::Function\n"
            "Properties:\n"
            "  Runtime: python3.12  # Use latest supported runtime"
        ),
    },
    
    "elbv2_waf_acl_attached": {
        "cli": (
            "# Create WAF Web ACL\n"
            "aws wafv2 create-web-acl \\\n"
            "  --name MyWebACL \\\n"
            "  --scope REGIONAL \\\n"
            "  --default-action Allow={} \\\n"
            "  --rules file://rules.json \\\n"
            "  --region <REGION>\n\n"
            "# Associate Web ACL with ALB\n"
            "aws wafv2 associate-web-acl \\\n"
            "  --web-acl-arn <WEB_ACL_ARN> \\\n"
            "  --resource-arn <ALB_ARN>"
        ),
        "terraform": (
            'resource "aws_wafv2_web_acl" "main" {\n'
            '  name  = "my-web-acl"\n'
            '  scope = "REGIONAL"\n'
            '  default_action {\n'
            '    allow {}\n'
            '  }\n'
            '  rule {\n'
            '    name     = "RateLimitRule"\n'
            '    priority = 1\n'
            '    action {\n'
            '      block {}\n'
            '    }\n'
            '    statement {\n'
            '      rate_based_statement {\n'
            '        limit              = 2000\n'
            '        aggregate_key_type = "IP"\n'
            '      }\n'
            '    }\n'
            '    visibility_config {\n'
            '      cloudwatch_metrics_enabled = true\n'
            '      metric_name               = "RateLimit"\n'
            '      sampled_requests_enabled  = true\n'
            '    }\n'
            '  }\n'
            '  visibility_config {\n'
            '    cloudwatch_metrics_enabled = true\n'
            '    metric_name               = "WebACL"\n'
            '    sampled_requests_enabled  = true\n'
            '  }\n'
            '}\n\n'
            'resource "aws_wafv2_web_acl_association" "alb" {\n'
            '  resource_arn = aws_lb.main.arn\n'
            '  web_acl_arn  = aws_wafv2_web_acl.main.arn\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::WAFv2::WebACLAssociation\n"
            "Properties:\n"
            "  ResourceArn: !Ref LoadBalancer\n"
            "  WebACLArn: !Ref WebACL"
        ),
    },
    
    "sns_topics_not_publicly_accessible": {
        "cli": (
            "# Remove public access from SNS topic policy\n"
            "aws sns set-topic-attributes \\\n"
            "  --topic-arn <TOPIC_ARN> \\\n"
            "  --attribute-name Policy \\\n"
            "  --attribute-value file://restricted-policy.json\n\n"
            "# Example restricted policy (save as restricted-policy.json):\n"
            "# {\n"
            "#   \"Version\": \"2012-10-17\",\n"
            "#   \"Statement\": [{\n"
            "#     \"Effect\": \"Allow\",\n"
            "#     \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:root\"},\n"
            "#     \"Action\": \"SNS:Publish\",\n"
            "#     \"Resource\": \"<TOPIC_ARN>\"\n"
            "#   }]\n"
            "# }"
        ),
        "terraform": (
            'resource "aws_sns_topic_policy" "restricted" {\n'
            '  arn = aws_sns_topic.main.arn\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }\n'
            '      Action    = ["SNS:Publish", "SNS:Subscribe"]\n'
            '      Resource  = aws_sns_topic.main.arn\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SNS::TopicPolicy\n"
            "Properties:\n"
            "  Topics:\n"
            "    - !Ref MyTopic\n"
            "  PolicyDocument:\n"
            "    Version: '2012-10-17'\n"
            "    Statement:\n"
            "      - Effect: Allow\n"
            "        Principal:\n"
            "          AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'\n"
            "        Action: SNS:Publish\n"
            "        Resource: !Ref MyTopic"
        ),
    },
    
    "sqs_queues_not_publicly_accessible": {
        "cli": (
            "# Update SQS queue policy to remove public access\n"
            "aws sqs set-queue-attributes \\\n"
            "  --queue-url <QUEUE_URL> \\\n"
            "  --attributes file://restricted-policy.json"
        ),
        "terraform": (
            'resource "aws_sqs_queue_policy" "restricted" {\n'
            '  queue_url = aws_sqs_queue.main.id\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }\n'
            '      Action    = "SQS:*"\n'
            '      Resource  = aws_sqs_queue.main.arn\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SQS::QueuePolicy\n"
            "Properties:\n"
            "  Queues:\n"
            "    - !Ref MyQueue\n"
            "  PolicyDocument:\n"
            "    Version: '2012-10-17'\n"
            "    Statement:\n"
            "      - Effect: Allow\n"
            "        Principal:\n"
            "          AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'\n"
            "        Action: SQS:*\n"
            "        Resource: !GetAtt MyQueue.Arn"
        ),
    },
    
    "redshift_cluster_audit_logging": {
        "cli": (
            "# Enable audit logging on Redshift cluster\n"
            "aws redshift modify-cluster \\\n"
            "  --cluster-identifier <CLUSTER_ID> \\\n"
            "  --logging-properties \\\n"
            "    BucketName=<S3_BUCKET>,\\\n"
            "    S3KeyPrefix=redshift-logs/,\\\n"
            "    LogDestinationType=s3"
        ),
        "terraform": (
            'resource "aws_redshift_cluster" "main" {\n'
            '  # ... existing config ...\n'
            '  logging {\n'
            '    enable        = true\n'
            '    bucket_name   = aws_s3_bucket.redshift_logs.id\n'
            '    s3_key_prefix = "redshift-logs/"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Redshift::Cluster\n"
            "Properties:\n"
            "  LoggingProperties:\n"
            "    BucketName: !Ref LogBucket\n"
            "    S3KeyPrefix: redshift-logs/"
        ),
    },
    
    "ecs_task_definition_no_privileged_containers": {
        "cli": (
            "# Remove privileged flag from task definition\n"
            "# Edit task definition JSON and re-register:\n"
            "# Change \"privileged\": true to \"privileged\": false\n"
            "aws ecs register-task-definition \\\n"
            "  --cli-input-json file://task-definition-fixed.json"
        ),
        "terraform": (
            'resource "aws_ecs_task_definition" "main" {\n'
            '  family = "my-app"\n'
            '  container_definitions = jsonencode([{\n'
            '    name  = "app"\n'
            '    image = "nginx:latest"\n'
            '    # ... other config ...\n'
            '    privileged = false  # Never set to true unless absolutely required\n'
            '    # If specific capabilities needed, use this instead:\n'
            '    # linuxParameters = {\n'
            '    #   capabilities = {\n'
            '    #     add = ["NET_ADMIN"]  # Grant only required capabilities\n'
            '    #   }\n'
            '    # }\n'
            '  }])\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ECS::TaskDefinition\n"
            "Properties:\n"
            "  ContainerDefinitions:\n"
            "    - Name: app\n"
            "      Image: nginx:latest\n"
            "      Privileged: false  # Never true unless absolutely required"
        ),
    },
    
    "eks_cluster_encryption_secrets_enabled": {
        "cli": (
            "# Create KMS key for EKS secrets encryption\n"
            "aws kms create-key \\\n"
            "  --description 'EKS secrets encryption key'\n\n"
            "# Create new EKS cluster with encryption (cannot enable on existing cluster)\n"
            "aws eks create-cluster \\\n"
            "  --name <CLUSTER_NAME> \\\n"
            "  --encryption-config '[{\n"
            "    \"resources\": [\"secrets\"],\n"
            "    \"provider\": {\n"
            "      \"keyArn\": \"<KMS_KEY_ARN>\"\n"
            "    }\n"
            "  }]' \\\n"
            "  # ... other required parameters ..."
        ),
        "terraform": (
            'resource "aws_kms_key" "eks" {\n'
            '  description = "EKS secrets encryption key"\n'
            '}\n\n'
            'resource "aws_eks_cluster" "main" {\n'
            '  name     = "my-cluster"\n'
            '  role_arn = aws_iam_role.eks_cluster.arn\n'
            '  encryption_config {\n'
            '    resources = ["secrets"]\n'
            '    provider {\n'
            '      key_arn = aws_kms_key.eks.arn\n'
            '    }\n'
            '  }\n'
            '  # ... other config ...\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EKS::Cluster\n"
            "Properties:\n"
            "  EncryptionConfig:\n"
            "    - Resources:\n"
            "        - secrets\n"
            "      Provider:\n"
            "        KeyArn: !GetAtt EKSKey.Arn"
        ),
    },
    
    "wafv2_webacl_logging_enabled": {
        "cli": (
            "# Enable WAF logging (requires Kinesis Data Firehose)\n"
            "aws wafv2 put-logging-configuration \\\n"
            "  --logging-configuration \\\n"
            "    ResourceArn=<WEB_ACL_ARN>,\\\n"
            "    LogDestinationConfigs=<KINESIS_FIREHOSE_ARN>"
        ),
        "terraform": (
            'resource "aws_wafv2_web_acl_logging_configuration" "main" {\n'
            '  resource_arn            = aws_wafv2_web_acl.main.arn\n'
            '  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::WAFv2::LoggingConfiguration\n"
            "Properties:\n"
            "  ResourceArn: !GetAtt WebACL.Arn\n"
            "  LogDestinationConfigs:\n"
            "    - !GetAtt FirehoseDeliveryStream.Arn"
        ),
    },
    
    "efs_encryption_at_rest_enabled": {
        "cli": (
            "# Create encrypted EFS file system (encryption at creation only)\n"
            "aws efs create-file-system \\\n"
            "  --encrypted \\\n"
            "  --kms-key-id <KMS_KEY_ARN> \\\n"
            "  --performance-mode generalPurpose \\\n"
            "  --throughput-mode bursting"
        ),
        "terraform": (
            'resource "aws_efs_file_system" "main" {\n'
            '  encrypted  = true\n'
            '  kms_key_id = aws_kms_key.efs.arn\n'
            '  performance_mode = "generalPurpose"\n'
            '  throughput_mode  = "bursting"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EFS::FileSystem\n"
            "Properties:\n"
            "  Encrypted: true\n"
            "  KmsKeyId: !Ref EFSKey\n"
            "  PerformanceMode: generalPurpose"
        ),
    },
    
    "sagemaker_notebook_instance_direct_internet_access_disabled": {
        "cli": (
            "# Create SageMaker notebook without direct internet access\n"
            "aws sagemaker create-notebook-instance \\\n"
            "  --notebook-instance-name <NAME> \\\n"
            "  --instance-type ml.t3.medium \\\n"
            "  --role-arn <ROLE_ARN> \\\n"
            "  --subnet-id <PRIVATE_SUBNET_ID> \\\n"
            "  --security-group-ids <SG_ID> \\\n"
            "  --direct-internet-access Disabled"
        ),
        "terraform": (
            'resource "aws_sagemaker_notebook_instance" "main" {\n'
            '  name                    = "my-notebook"\n'
            '  instance_type           = "ml.t3.medium"\n'
            '  role_arn                = aws_iam_role.sagemaker.arn\n'
            '  subnet_id               = aws_subnet.private.id\n'
            '  security_groups         = [aws_security_group.sagemaker.id]\n'
            '  direct_internet_access  = "Disabled"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SageMaker::NotebookInstance\n"
            "Properties:\n"
            "  DirectInternetAccess: Disabled\n"
            "  SubnetId: !Ref PrivateSubnet\n"
            "  SecurityGroupIds:\n"
            "    - !Ref SageMakerSecurityGroup"
        ),
    },
    
    "elasticache_redis_cluster_encryption_at_rest_enabled": {
        "cli": (
            "# Create encrypted ElastiCache Redis cluster (encryption at creation only)\n"
            "aws elasticache create-replication-group \\\n"
            "  --replication-group-id my-cluster \\\n"
            "  --replication-group-description 'Encrypted cluster' \\\n"
            "  --engine redis \\\n"
            "  --cache-node-type cache.t3.small \\\n"
            "  --at-rest-encryption-enabled \\\n"
            "  --transit-encryption-enabled \\\n"
            "  --auth-token <STRONG_PASSWORD>"
        ),
        "terraform": (
            'resource "aws_elasticache_replication_group" "main" {\n'
            '  replication_group_id       = "my-cluster"\n'
            '  replication_group_description = "Encrypted Redis cluster"\n'
            '  engine                     = "redis"\n'
            '  node_type                  = "cache.t3.small"\n'
            '  number_cache_clusters      = 2\n'
            '  at_rest_encryption_enabled = true\n'
            '  transit_encryption_enabled = true\n'
            '  auth_token                 = var.redis_auth_token\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ElastiCache::ReplicationGroup\n"
            "Properties:\n"
            "  AtRestEncryptionEnabled: true\n"
            "  TransitEncryptionEnabled: true\n"
            "  AuthToken: !Ref RedisAuthToken"
        ),
    },
}

print(f"[IAC_BATCH_3] Added {len(IAC_BATCH_3)} additional IaC template sets")
print(f"[IAC_BATCH_3] Each set includes CLI + Terraform + CloudFormation remediation")

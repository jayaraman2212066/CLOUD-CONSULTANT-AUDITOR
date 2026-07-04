"""
IAC_BATCH_4: Advanced Infrastructure as Code Templates
Additional remediation templates for comprehensive AWS security coverage
Each entry includes AWS CLI, Terraform, and CloudFormation remediation code
"""

IAC_BATCH_4 = {
    "kms_key_not_publicly_accessible": {
        "cli": (
            "# Update KMS key policy to remove public access\n"
            "aws kms put-key-policy \\\n"
            "  --key-id <KEY_ID> \\\n"
            "  --policy-name default \\\n"
            "  --policy '{\n"
            "    \"Version\": \"2012-10-17\",\n"
            "    \"Statement\": [{\n"
            "      \"Sid\": \"Enable IAM User Permissions\",\n"
            "      \"Effect\": \"Allow\",\n"
            "      \"Principal\": {\"AWS\": \"arn:aws:iam::<ACCOUNT_ID>:root\"},\n"
            "      \"Action\": \"kms:*\",\n"
            "      \"Resource\": \"*\"\n"
            "    }]\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_kms_key" "main" {\n'
            '  description = "Private KMS key"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Sid    = "Enable IAM User Permissions"\n'
            '      Effect = "Allow"\n'
            '      Principal = {\n'
            '        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"\n'
            '      }\n'
            '      Action   = "kms:*"\n'
            '      Resource = "*"\n'
            '    }]\n'
            '  })\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::KMS::Key\n"
            "Properties:\n"
            "  KeyPolicy:\n"
            "    Version: '2012-10-17'\n"
            "    Statement:\n"
            "      - Sid: Enable IAM User Permissions\n"
            "        Effect: Allow\n"
            "        Principal:\n"
            "          AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'\n"
            "        Action: 'kms:*'\n"
            "        Resource: '*'"
        ),
    },
    
    "sns_topics_not_publicly_accessible": {
        "cli": (
            "# Update SNS topic policy to restrict access\n"
            "aws sns set-topic-attributes \\\n"
            "  --topic-arn <TOPIC_ARN> \\\n"
            "  --attribute-name Policy \\\n"
            "  --attribute-value '{\n"
            "    \"Version\": \"2012-10-17\",\n"
            "    \"Statement\": [{\n"
            "      \"Effect\": \"Allow\",\n"
            "      \"Principal\": {\"AWS\": \"arn:aws:iam::<ACCOUNT_ID>:root\"},\n"
            "      \"Action\": \"SNS:Publish\",\n"
            "      \"Resource\": \"<TOPIC_ARN>\"\n"
            "    }]\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_sns_topic" "main" {\n'
            '  name = "private-topic"\n'
            '}\n\n'
            'resource "aws_sns_topic_policy" "main" {\n'
            '  arn = aws_sns_topic.main.arn\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Principal = {\n'
            '        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"\n'
            '      }\n'
            '      Action   = "SNS:Publish"\n'
            '      Resource = aws_sns_topic.main.arn\n'
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
            "# Update SQS queue policy to restrict access\n"
            "aws sqs set-queue-attributes \\\n"
            "  --queue-url <QUEUE_URL> \\\n"
            "  --attributes Policy='{\n"
            "    \"Version\": \"2012-10-17\",\n"
            "    \"Statement\": [{\n"
            "      \"Effect\": \"Allow\",\n"
            "      \"Principal\": {\"AWS\": \"arn:aws:iam::<ACCOUNT_ID>:root\"},\n"
            "      \"Action\": \"SQS:*\",\n"
            "      \"Resource\": \"<QUEUE_ARN>\"\n"
            "    }]\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_sqs_queue" "main" {\n'
            '  name = "private-queue"\n'
            '}\n\n'
            'resource "aws_sqs_queue_policy" "main" {\n'
            '  queue_url = aws_sqs_queue.main.id\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n'
            '      Effect = "Allow"\n'
            '      Principal = {\n'
            '        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"\n'
            '      }\n'
            '      Action   = "SQS:*"\n'
            '      Resource = aws_sqs_queue.main.arn\n'
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
            "        Action: 'SQS:*'\n"
            "        Resource: !GetAtt MyQueue.Arn"
        ),
    },
    
    "efs_encryption_at_rest_enabled": {
        "cli": (
            "# Create encrypted EFS file system (encryption must be enabled at creation)\n"
            "aws efs create-file-system \\\n"
            "  --encrypted \\\n"
            "  --kms-key-id <KMS_KEY_ID> \\\n"
            "  --performance-mode generalPurpose \\\n"
            "  --throughput-mode bursting \\\n"
            "  --tags Key=Name,Value=EncryptedEFS"
        ),
        "terraform": (
            'resource "aws_efs_file_system" "main" {\n'
            '  encrypted  = true\n'
            '  kms_key_id = aws_kms_key.efs.arn\n'
            '  \n'
            '  tags = {\n'
            '    Name = "EncryptedEFS"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EFS::FileSystem\n"
            "Properties:\n"
            "  Encrypted: true\n"
            "  KmsKeyId: !Ref EFSKMSKey\n"
            "  PerformanceMode: generalPurpose\n"
            "  ThroughputMode: bursting"
        ),
    },
    
    "elasticsearch_domain_node_to_node_encryption": {
        "cli": (
            "# Node-to-node encryption must be enabled at domain creation\n"
            "aws es create-elasticsearch-domain \\\n"
            "  --domain-name <DOMAIN_NAME> \\\n"
            "  --node-to-node-encryption-options Enabled=true \\\n"
            "  --encryption-at-rest-options Enabled=true,KmsKeyId=<KEY_ID>"
        ),
        "terraform": (
            'resource "aws_elasticsearch_domain" "main" {\n'
            '  domain_name = "secure-domain"\n'
            '  \n'
            '  node_to_node_encryption {\n'
            '    enabled = true\n'
            '  }\n'
            '  \n'
            '  encrypt_at_rest {\n'
            '    enabled    = true\n'
            '    kms_key_id = aws_kms_key.es.arn\n'
            '  }\n'
            '  \n'
            '  domain_endpoint_options {\n'
            '    enforce_https       = true\n'
            '    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Elasticsearch::Domain\n"
            "Properties:\n"
            "  NodeToNodeEncryptionOptions:\n"
            "    Enabled: true\n"
            "  EncryptionAtRestOptions:\n"
            "    Enabled: true\n"
            "    KmsKeyId: !Ref ESKMSKey\n"
            "  DomainEndpointOptions:\n"
            "    EnforceHTTPS: true\n"
            "    TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07"
        ),
    },
    
    "vpc_subnet_auto_assign_public_ip_disabled": {
        "cli": (
            "# Disable auto-assign public IP for subnet\n"
            "aws ec2 modify-subnet-attribute \\\n"
            "  --subnet-id <SUBNET_ID> \\\n"
            "  --no-map-public-ip-on-launch"
        ),
        "terraform": (
            'resource "aws_subnet" "private" {\n'
            '  vpc_id                  = aws_vpc.main.id\n'
            '  cidr_block              = "10.0.1.0/24"\n'
            '  map_public_ip_on_launch = false\n'
            '  \n'
            '  tags = {\n'
            '    Name = "Private Subnet"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EC2::Subnet\n"
            "Properties:\n"
            "  VpcId: !Ref VPC\n"
            "  CidrBlock: 10.0.1.0/24\n"
            "  MapPublicIpOnLaunch: false\n"
            "  Tags:\n"
            "    - Key: Name\n"
            "      Value: Private Subnet"
        ),
    },
    
    "guardduty_enabled_all_regions": {
        "cli": (
            "# Enable GuardDuty in all regions\n"
            "for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n"
            "  echo \"Enabling GuardDuty in $region\"\n"
            "  aws guardduty create-detector --enable --region $region\n"
            "done"
        ),
        "terraform": (
            '# Enable GuardDuty in multiple regions using provider alias\n'
            'provider "aws" {\n'
            '  alias  = "us_east_1"\n'
            '  region = "us-east-1"\n'
            '}\n\n'
            'provider "aws" {\n'
            '  alias  = "us_west_2"\n'
            '  region = "us-west-2"\n'
            '}\n\n'
            'resource "aws_guardduty_detector" "us_east" {\n'
            '  provider = aws.us_east_1\n'
            '  enable   = true\n'
            '}\n\n'
            'resource "aws_guardduty_detector" "us_west" {\n'
            '  provider = aws.us_west_2\n'
            '  enable   = true\n'
            '}'
        ),
        "cloudformation": (
            "# Deploy StackSet across all regions\n"
            "Type: AWS::GuardDuty::Detector\n"
            "Properties:\n"
            "  Enable: true\n"
            "  FindingPublishingFrequency: FIFTEEN_MINUTES"
        ),
    },
    
    "accessanalyzer_enabled": {
        "cli": (
            "# Enable IAM Access Analyzer\n"
            "aws accessanalyzer create-analyzer \\\n"
            "  --analyzer-name my-account-analyzer \\\n"
            "  --type ACCOUNT \\\n"
            "  --region <REGION>"
        ),
        "terraform": (
            'resource "aws_accessanalyzer_analyzer" "main" {\n'
            '  analyzer_name = "account-analyzer"\n'
            '  type          = "ACCOUNT"\n'
            '  \n'
            '  tags = {\n'
            '    Name = "Account Analyzer"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::AccessAnalyzer::Analyzer\n"
            "Properties:\n"
            "  AnalyzerName: account-analyzer\n"
            "  Type: ACCOUNT\n"
            "  Tags:\n"
            "    - Key: Name\n"
            "      Value: Account Analyzer"
        ),
    },
    
    "macie_is_enabled": {
        "cli": (
            "# Enable Amazon Macie\n"
            "aws macie2 enable-macie --region <REGION>\n\n"
            "# Create classification job\n"
            "aws macie2 create-classification-job \\\n"
            "  --job-type ONE_TIME \\\n"
            "  --s3-job-definition bucketDefinitions=[{accountId=<ACCOUNT_ID>,buckets=[<BUCKET_NAME>]}] \\\n"
            "  --name \"S3-PII-Discovery\" \\\n"
            "  --region <REGION>"
        ),
        "terraform": (
            'resource "aws_macie2_account" "main" {\n'
            '  finding_publishing_frequency = "FIFTEEN_MINUTES"\n'
            '  status                        = "ENABLED"\n'
            '}\n\n'
            'resource "aws_macie2_classification_job" "main" {\n'
            '  job_type = "ONE_TIME"\n'
            '  name     = "S3-PII-Discovery"\n'
            '  \n'
            '  s3_job_definition {\n'
            '    bucket_definitions {\n'
            '      account_id = data.aws_caller_identity.current.account_id\n'
            '      buckets    = [aws_s3_bucket.sensitive.id]\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "# Macie configuration via AWS Console\n"
            "# CloudFormation support limited"
        ),
    },
    
    "sagemaker_notebook_instance_encryption_enabled": {
        "cli": (
            "# Create encrypted SageMaker notebook instance\n"
            "aws sagemaker create-notebook-instance \\\n"
            "  --notebook-instance-name <INSTANCE_NAME> \\\n"
            "  --instance-type ml.t2.medium \\\n"
            "  --role-arn <ROLE_ARN> \\\n"
            "  --kms-key-id <KMS_KEY_ID> \\\n"
            "  --direct-internet-access Disabled \\\n"
            "  --subnet-id <SUBNET_ID> \\\n"
            "  --security-group-ids <SG_ID>"
        ),
        "terraform": (
            'resource "aws_sagemaker_notebook_instance" "main" {\n'
            '  name                    = "secure-notebook"\n'
            '  instance_type           = "ml.t2.medium"\n'
            '  role_arn                = aws_iam_role.sagemaker.arn\n'
            '  kms_key_id              = aws_kms_key.sagemaker.id\n'
            '  direct_internet_access  = "Disabled"\n'
            '  subnet_id               = aws_subnet.private.id\n'
            '  security_groups         = [aws_security_group.sagemaker.id]\n'
            '  \n'
            '  tags = {\n'
            '    Name = "Secure SageMaker Notebook"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SageMaker::NotebookInstance\n"
            "Properties:\n"
            "  NotebookInstanceName: secure-notebook\n"
            "  InstanceType: ml.t2.medium\n"
            "  RoleArn: !GetAtt SageMakerRole.Arn\n"
            "  KmsKeyId: !Ref SageMakerKMSKey\n"
            "  DirectInternetAccess: Disabled\n"
            "  SubnetId: !Ref PrivateSubnet\n"
            "  SecurityGroupIds:\n"
            "    - !Ref SageMakerSecurityGroup"
        ),
    },
    
    "elasticache_redis_cluster_encryption_at_rest": {
        "cli": (
            "# Create encrypted ElastiCache Redis cluster\n"
            "aws elasticache create-replication-group \\\n"
            "  --replication-group-id <GROUP_ID> \\\n"
            "  --replication-group-description \"Encrypted Redis cluster\" \\\n"
            "  --engine redis \\\n"
            "  --cache-node-type cache.t3.micro \\\n"
            "  --at-rest-encryption-enabled \\\n"
            "  --transit-encryption-enabled \\\n"
            "  --auth-token <STRONG_PASSWORD> \\\n"
            "  --kms-key-id <KMS_KEY_ID>"
        ),
        "terraform": (
            'resource "aws_elasticache_replication_group" "main" {\n'
            '  replication_group_id       = "encrypted-redis"\n'
            '  replication_group_description = "Encrypted Redis cluster"\n'
            '  engine                     = "redis"\n'
            '  node_type                  = "cache.t3.micro"\n'
            '  at_rest_encryption_enabled = true\n'
            '  transit_encryption_enabled = true\n'
            '  auth_token                 = random_password.redis.result\n'
            '  kms_key_id                 = aws_kms_key.elasticache.arn\n'
            '  automatic_failover_enabled = true\n'
            '  \n'
            '  num_cache_clusters = 2\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ElastiCache::ReplicationGroup\n"
            "Properties:\n"
            "  ReplicationGroupId: encrypted-redis\n"
            "  ReplicationGroupDescription: Encrypted Redis cluster\n"
            "  Engine: redis\n"
            "  CacheNodeType: cache.t3.micro\n"
            "  AtRestEncryptionEnabled: true\n"
            "  TransitEncryptionEnabled: true\n"
            "  AuthToken: !Ref RedisAuthToken\n"
            "  KmsKeyId: !Ref ElastiCacheKMSKey\n"
            "  AutomaticFailoverEnabled: true\n"
            "  NumCacheClusters: 2"
        ),
    },
    
    "codebuild_project_no_secrets_in_variables": {
        "cli": (
            "# Update CodeBuild project to use Secrets Manager\n"
            "aws codebuild update-project \\\n"
            "  --name <PROJECT_NAME> \\\n"
            "  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL,environmentVariables='[\n"
            "    {\n"
            "      \"name\": \"DB_PASSWORD\",\n"
            "      \"type\": \"SECRETS_MANAGER\",\n"
            "      \"value\": \"<SECRET_ARN>\"\n"
            "    }\n"
            "  ]'"
        ),
        "terraform": (
            'resource "aws_codebuild_project" "main" {\n'
            '  name = "secure-build"\n'
            '  \n'
            '  environment {\n'
            '    compute_type = "BUILD_GENERAL1_SMALL"\n'
            '    image        = "aws/codebuild/standard:5.0"\n'
            '    type         = "LINUX_CONTAINER"\n'
            '    \n'
            '    environment_variable {\n'
            '      name  = "DB_PASSWORD"\n'
            '      type  = "SECRETS_MANAGER"\n'
            '      value = aws_secretsmanager_secret.db.arn\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  # ... other configuration ...\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::CodeBuild::Project\n"
            "Properties:\n"
            "  Environment:\n"
            "    ComputeType: BUILD_GENERAL1_SMALL\n"
            "    Image: aws/codebuild/standard:5.0\n"
            "    Type: LINUX_CONTAINER\n"
            "    EnvironmentVariables:\n"
            "      - Name: DB_PASSWORD\n"
            "        Type: SECRETS_MANAGER\n"
            "        Value: !Ref DBSecret"
        ),
    },
    
    "wafv2_webacl_logging_enabled": {
        "cli": (
            "# Enable WAFv2 logging\n"
            "aws wafv2 put-logging-configuration \\\n"
            "  --logging-configuration ResourceArn=<WEB_ACL_ARN>,LogDestinationConfigs=<KINESIS_ARN> \\\n"
            "  --region <REGION>"
        ),
        "terraform": (
            'resource "aws_wafv2_web_acl_logging_configuration" "main" {\n'
            '  resource_arn            = aws_wafv2_web_acl.main.arn\n'
            '  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]\n'
            '}\n\n'
            'resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {\n'
            '  name        = "aws-waf-logs-delivery"\n'
            '  destination = "extended_s3"\n'
            '  \n'
            '  extended_s3_configuration {\n'
            '    role_arn   = aws_iam_role.firehose.arn\n'
            '    bucket_arn = aws_s3_bucket.waf_logs.arn\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::WAFv2::LoggingConfiguration\n"
            "Properties:\n"
            "  ResourceArn: !GetAtt WebACL.Arn\n"
            "  LogDestinationConfigs:\n"
            "    - !GetAtt WAFLogsDeliveryStream.Arn"
        ),
    },
    
    "eks_cluster_encryption_secrets_enabled": {
        "cli": (
            "# Encryption must be enabled at cluster creation\n"
            "aws eks create-cluster \\\n"
            "  --name <CLUSTER_NAME> \\\n"
            "  --role-arn <ROLE_ARN> \\\n"
            "  --resources-vpc-config subnetIds=<SUBNET_IDS>,securityGroupIds=<SG_IDS> \\\n"
            "  --encryption-config resources=secrets,provider={keyArn=<KMS_KEY_ARN>}"
        ),
        "terraform": (
            'resource "aws_eks_cluster" "main" {\n'
            '  name     = "secure-cluster"\n'
            '  role_arn = aws_iam_role.eks.arn\n'
            '  \n'
            '  encryption_config {\n'
            '    resources = ["secrets"]\n'
            '    \n'
            '    provider {\n'
            '      key_arn = aws_kms_key.eks.arn\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  vpc_config {\n'
            '    subnet_ids              = aws_subnet.private[*].id\n'
            '    endpoint_private_access = true\n'
            '    endpoint_public_access  = false\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EKS::Cluster\n"
            "Properties:\n"
            "  Name: secure-cluster\n"
            "  RoleArn: !GetAtt EKSRole.Arn\n"
            "  EncryptionConfig:\n"
            "    - Resources:\n"
            "        - secrets\n"
            "      Provider:\n"
            "        KeyArn: !GetAtt EKSKMSKey.Arn\n"
            "  ResourcesVpcConfig:\n"
            "    SubnetIds: !Ref PrivateSubnets\n"
            "    EndpointPrivateAccess: true\n"
            "    EndpointPublicAccess: false"
        ),
    },
}

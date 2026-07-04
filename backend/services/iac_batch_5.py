"""
IAC_BATCH_5: Extended Infrastructure as Code Templates
Additional remediation templates for comprehensive coverage
Each entry includes AWS CLI, Terraform, and CloudFormation remediation code
"""

IAC_BATCH_5 = {
    "cloudtrail_multi_region_enabled": {
        "cli": (
            "# Enable multi-region CloudTrail\n"
            "aws cloudtrail create-trail \\\n"
            "  --name my-cloudtrail \\\n"
            "  --s3-bucket-name <BUCKET_NAME> \\\n"
            "  --is-multi-region-trail \\\n"
            "  --enable-log-file-validation\n\n"
            "# Start logging\n"
            "aws cloudtrail start-logging --name my-cloudtrail"
        ),
        "terraform": (
            'resource "aws_cloudtrail" "main" {\n'
            '  name                          = "multi-region-trail"\n'
            '  s3_bucket_name                = aws_s3_bucket.cloudtrail.id\n'
            '  is_multi_region_trail         = true\n'
            '  enable_log_file_validation    = true\n'
            '  include_global_service_events = true\n'
            '  \n'
            '  event_selector {\n'
            '    read_write_type           = "All"\n'
            '    include_management_events = true\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::CloudTrail::Trail\n"
            "Properties:\n"
            "  TrailName: multi-region-trail\n"
            "  S3BucketName: !Ref CloudTrailBucket\n"
            "  IsMultiRegionTrail: true\n"
            "  EnableLogFileValidation: true\n"
            "  IncludeGlobalServiceEvents: true\n"
            "  IsLogging: true"
        ),
    },
    
    "config_enabled_all_regions": {
        "cli": (
            "# Enable AWS Config in all regions\n"
            "for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do\n"
            "  echo \"Enabling Config in $region\"\n"
            "  aws configservice put-configuration-recorder \\\n"
            "    --configuration-recorder name=default,roleARN=<ROLE_ARN> \\\n"
            "    --recording-group allSupported=true,includeGlobalResourceTypes=true \\\n"
            "    --region $region\n"
            "  \n"
            "  aws configservice put-delivery-channel \\\n"
            "    --delivery-channel name=default,s3BucketName=<BUCKET> \\\n"
            "    --region $region\n"
            "  \n"
            "  aws configservice start-configuration-recorder \\\n"
            "    --configuration-recorder-name default \\\n"
            "    --region $region\n"
            "done"
        ),
        "terraform": (
            '# Use module to deploy across regions\n'
            'module "config_us_east" {\n'
            '  source = "./modules/aws-config"\n'
            '  providers = {\n'
            '    aws = aws.us_east_1\n'
            '  }\n'
            '}\n\n'
            'module "config_us_west" {\n'
            '  source = "./modules/aws-config"\n'
            '  providers = {\n'
            '    aws = aws.us_west_2\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "# Deploy via StackSets across all regions\n"
            "Type: AWS::Config::ConfigurationRecorder\n"
            "Properties:\n"
            "  RoleArn: !GetAtt ConfigRole.Arn\n"
            "  RecordingGroup:\n"
            "    AllSupported: true\n"
            "    IncludeGlobalResourceTypes: true"
        ),
    },
    
    "securityhub_enabled": {
        "cli": (
            "# Enable Security Hub\n"
            "aws securityhub enable-security-hub \\\n"
            "  --enable-default-standards \\\n"
            "  --region <REGION>\n\n"
            "# Subscribe to security standards\n"
            "aws securityhub batch-enable-standards \\\n"
            "  --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0 \\\n"
            "  --region <REGION>"
        ),
        "terraform": (
            'resource "aws_securityhub_account" "main" {}\n\n'
            'resource "aws_securityhub_standards_subscription" "cis" {\n'
            '  depends_on    = [aws_securityhub_account.main]\n'
            '  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"\n'
            '}\n\n'
            'resource "aws_securityhub_standards_subscription" "aws_foundational" {\n'
            '  depends_on    = [aws_securityhub_account.main]\n'
            '  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::SecurityHub::Hub\n"
            "Properties:\n"
            "  Tags:\n"
            "    Key: Environment\n"
            "    Value: Production"
        ),
    },
    
    "emr_cluster_kerberos_enabled": {
        "cli": (
            "# Create EMR cluster with Kerberos authentication\n"
            "aws emr create-cluster \\\n"
            "  --name \"Secure EMR Cluster\" \\\n"
            "  --release-label emr-6.10.0 \\\n"
            "  --instance-type m5.xlarge \\\n"
            "  --instance-count 3 \\\n"
            "  --ec2-attributes KeyName=<KEY_PAIR>,SubnetId=<PRIVATE_SUBNET> \\\n"
            "  --kerberos-attributes Realm=EC2.INTERNAL,KdcAdminPassword=<STRONG_PASSWORD>"
        ),
        "terraform": (
            'resource "aws_emr_cluster" "main" {\n'
            '  name          = "secure-emr-cluster"\n'
            '  release_label = "emr-6.10.0"\n'
            '  \n'
            '  ec2_attributes {\n'
            '    key_name                          = aws_key_pair.emr.key_name\n'
            '    subnet_id                         = aws_subnet.private.id\n'
            '    emr_managed_master_security_group = aws_security_group.emr_master.id\n'
            '    emr_managed_slave_security_group  = aws_security_group.emr_slave.id\n'
            '  }\n'
            '  \n'
            '  kerberos_attributes {\n'
            '    realm                      = "EC2.INTERNAL"\n'
            '    kdc_admin_password         = random_password.kerberos.result\n'
            '    cross_realm_trust_principal_password = random_password.cross_realm.result\n'
            '  }\n'
            '  \n'
            '  master_instance_group {\n'
            '    instance_type = "m5.xlarge"\n'
            '  }\n'
            '  \n'
            '  core_instance_group {\n'
            '    instance_type  = "m5.xlarge"\n'
            '    instance_count = 2\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::EMR::Cluster\n"
            "Properties:\n"
            "  Name: secure-emr-cluster\n"
            "  ReleaseLabel: emr-6.10.0\n"
            "  KerberosAttributes:\n"
            "    Realm: EC2.INTERNAL\n"
            "    KdcAdminPassword: !Ref KerberosPassword\n"
            "  Instances:\n"
            "    MasterInstanceGroup:\n"
            "      InstanceType: m5.xlarge\n"
            "      InstanceCount: 1\n"
            "    CoreInstanceGroup:\n"
            "      InstanceType: m5.xlarge\n"
            "      InstanceCount: 2"
        ),
    },
    
    "neptune_cluster_iam_authentication_enabled": {
        "cli": (
            "# Modify Neptune cluster to enable IAM authentication\n"
            "aws neptune modify-db-cluster \\\n"
            "  --db-cluster-identifier <CLUSTER_ID> \\\n"
            "  --enable-iam-database-authentication \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_neptune_cluster" "main" {\n'
            '  cluster_identifier                  = "secure-neptune"\n'
            '  engine                              = "neptune"\n'
            '  backup_retention_period             = 7\n'
            '  preferred_backup_window             = "07:00-09:00"\n'
            '  skip_final_snapshot                 = false\n'
            '  iam_database_authentication_enabled = true\n'
            '  storage_encrypted                   = true\n'
            '  kms_key_arn                         = aws_kms_key.neptune.arn\n'
            '  \n'
            '  vpc_security_group_ids = [aws_security_group.neptune.id]\n'
            '  db_subnet_group_name   = aws_neptune_subnet_group.main.name\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Neptune::DBCluster\n"
            "Properties:\n"
            "  DBClusterIdentifier: secure-neptune\n"
            "  IamAuthEnabled: true\n"
            "  StorageEncrypted: true\n"
            "  KmsKeyId: !Ref NeptuneKMSKey\n"
            "  BackupRetentionPeriod: 7\n"
            "  VpcSecurityGroupIds:\n"
            "    - !Ref NeptuneSecurityGroup\n"
            "  DBSubnetGroupName: !Ref NeptuneSubnetGroup"
        ),
    },
    
    "documentdb_cluster_audit_logging_enabled": {
        "cli": (
            "# Enable audit logging for DocumentDB\n"
            "aws docdb modify-db-cluster \\\n"
            "  --db-cluster-identifier <CLUSTER_ID> \\\n"
            "  --cloudwatch-logs-export-configuration EnableLogTypes=audit \\\n"
            "  --apply-immediately"
        ),
        "terraform": (
            'resource "aws_docdb_cluster" "main" {\n'
            '  cluster_identifier              = "secure-docdb"\n'
            '  engine                          = "docdb"\n'
            '  master_username                 = "admin"\n'
            '  master_password                 = random_password.docdb.result\n'
            '  backup_retention_period         = 7\n'
            '  preferred_backup_window         = "07:00-09:00"\n'
            '  skip_final_snapshot             = false\n'
            '  storage_encrypted               = true\n'
            '  kms_key_id                      = aws_kms_key.docdb.arn\n'
            '  enabled_cloudwatch_logs_exports = ["audit", "profiler"]\n'
            '  \n'
            '  vpc_security_group_ids = [aws_security_group.docdb.id]\n'
            '  db_subnet_group_name   = aws_docdb_subnet_group.main.name\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::DocDB::DBCluster\n"
            "Properties:\n"
            "  DBClusterIdentifier: secure-docdb\n"
            "  MasterUsername: admin\n"
            "  MasterUserPassword: !Ref DocDBPassword\n"
            "  StorageEncrypted: true\n"
            "  KmsKeyId: !Ref DocDBKMSKey\n"
            "  EnableCloudwatchLogsExports:\n"
            "    - audit\n"
            "    - profiler\n"
            "  BackupRetentionPeriod: 7\n"
            "  VpcSecurityGroupIds:\n"
            "    - !Ref DocDBSecurityGroup\n"
            "  DBSubnetGroupName: !Ref DocDBSubnetGroup"
        ),
    },
    
    "athena_workgroup_encryption_enabled": {
        "cli": (
            "# Create Athena workgroup with encryption\n"
            "aws athena create-work-group \\\n"
            "  --name secure-workgroup \\\n"
            "  --configuration '{\n"
            "    \"ResultConfigurationUpdates\": {\n"
            "      \"OutputLocation\": \"s3://<BUCKET>/results/\",\n"
            "      \"EncryptionConfiguration\": {\n"
            "        \"EncryptionOption\": \"SSE_KMS\",\n"
            "        \"KmsKey\": \"<KMS_KEY_ARN>\"\n"
            "      }\n"
            "    },\n"
            "    \"EnforceWorkGroupConfiguration\": true\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_athena_workgroup" "main" {\n'
            '  name = "secure-workgroup"\n'
            '  \n'
            '  configuration {\n'
            '    enforce_workgroup_configuration    = true\n'
            '    publish_cloudwatch_metrics_enabled = true\n'
            '    \n'
            '    result_configuration {\n'
            '      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"\n'
            '      \n'
            '      encryption_configuration {\n'
            '        encryption_option = "SSE_KMS"\n'
            '        kms_key_arn       = aws_kms_key.athena.arn\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  tags = {\n'
            '    Name = "Secure Athena Workgroup"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Athena::WorkGroup\n"
            "Properties:\n"
            "  Name: secure-workgroup\n"
            "  WorkGroupConfiguration:\n"
            "    EnforceWorkGroupConfiguration: true\n"
            "    PublishCloudWatchMetricsEnabled: true\n"
            "    ResultConfiguration:\n"
            "      OutputLocation: !Sub 's3://${AthenaResultsBucket}/results/'\n"
            "      EncryptionConfiguration:\n"
            "        EncryptionOption: SSE_KMS\n"
            "        KmsKey: !GetAtt AthenaKMSKey.Arn"
        ),
    },
    
    "glue_data_catalog_encryption_enabled": {
        "cli": (
            "# Enable Glue Data Catalog encryption\n"
            "aws glue put-data-catalog-encryption-settings \\\n"
            "  --data-catalog-encryption-settings '{\n"
            "    \"EncryptionAtRest\": {\n"
            "      \"CatalogEncryptionMode\": \"SSE-KMS\",\n"
            "      \"SseAwsKmsKeyId\": \"<KMS_KEY_ARN>\"\n"
            "    },\n"
            "    \"ConnectionPasswordEncryption\": {\n"
            "      \"ReturnConnectionPasswordEncrypted\": true,\n"
            "      \"AwsKmsKeyId\": \"<KMS_KEY_ARN>\"\n"
            "    }\n"
            "  }'"
        ),
        "terraform": (
            'resource "aws_glue_data_catalog_encryption_settings" "main" {\n'
            '  data_catalog_encryption_settings {\n'
            '    connection_password_encryption {\n'
            '      aws_kms_key_id                       = aws_kms_key.glue.arn\n'
            '      return_connection_password_encrypted = true\n'
            '    }\n'
            '    \n'
            '    encryption_at_rest {\n'
            '      catalog_encryption_mode = "SSE-KMS"\n'
            '      sse_aws_kms_key_id      = aws_kms_key.glue.arn\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::Glue::DataCatalogEncryptionSettings\n"
            "Properties:\n"
            "  CatalogId: !Ref AWS::AccountId\n"
            "  DataCatalogEncryptionSettings:\n"
            "    EncryptionAtRest:\n"
            "      CatalogEncryptionMode: SSE-KMS\n"
            "      SseAwsKmsKeyId: !GetAtt GlueKMSKey.Arn\n"
            "    ConnectionPasswordEncryption:\n"
            "      ReturnConnectionPasswordEncrypted: true\n"
            "      KmsKeyId: !GetAtt GlueKMSKey.Arn"
        ),
    },
    
    "api_gateway_xray_tracing_enabled": {
        "cli": (
            "# Enable X-Ray tracing for API Gateway\n"
            "aws apigateway update-stage \\\n"
            "  --rest-api-id <API_ID> \\\n"
            "  --stage-name <STAGE_NAME> \\\n"
            "  --patch-operations op=replace,path=/tracingEnabled,value=true"
        ),
        "terraform": (
            'resource "aws_api_gateway_stage" "main" {\n'
            '  deployment_id = aws_api_gateway_deployment.main.id\n'
            '  rest_api_id   = aws_api_gateway_rest_api.main.id\n'
            '  stage_name    = "prod"\n'
            '  \n'
            '  xray_tracing_enabled = true\n'
            '  \n'
            '  access_log_settings {\n'
            '    destination_arn = aws_cloudwatch_log_group.api_gateway.arn\n'
            '    format         = "$requestId"\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::ApiGateway::Stage\n"
            "Properties:\n"
            "  RestApiId: !Ref MyAPI\n"
            "  DeploymentId: !Ref Deployment\n"
            "  StageName: prod\n"
            "  TracingEnabled: true\n"
            "  AccessLogSetting:\n"
            "    DestinationArn: !GetAtt APILogGroup.Arn\n"
            "    Format: $requestId"
        ),
    },
    
    "cloudfront_distribution_encryption_in_transit": {
        "cli": (
            "# Update CloudFront distribution to enforce HTTPS\n"
            "aws cloudfront update-distribution \\\n"
            "  --id <DISTRIBUTION_ID> \\\n"
            "  --distribution-config file://distribution-config.json\n\n"
            "# distribution-config.json should have:\n"
            "# \"ViewerProtocolPolicy\": \"redirect-to-https\""
        ),
        "terraform": (
            'resource "aws_cloudfront_distribution" "main" {\n'
            '  enabled = true\n'
            '  \n'
            '  origin {\n'
            '    domain_name = aws_s3_bucket.main.bucket_regional_domain_name\n'
            '    origin_id   = "S3-Origin"\n'
            '    \n'
            '    s3_origin_config {\n'
            '      origin_access_identity = aws_cloudfront_origin_access_identity.main.cloudfront_access_identity_path\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  default_cache_behavior {\n'
            '    target_origin_id       = "S3-Origin"\n'
            '    viewer_protocol_policy = "redirect-to-https"\n'
            '    \n'
            '    allowed_methods = ["GET", "HEAD"]\n'
            '    cached_methods  = ["GET", "HEAD"]\n'
            '    \n'
            '    forwarded_values {\n'
            '      query_string = false\n'
            '      cookies {\n'
            '        forward = "none"\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  viewer_certificate {\n'
            '    cloudfront_default_certificate = false\n'
            '    acm_certificate_arn            = aws_acm_certificate.main.arn\n'
            '    ssl_support_method             = "sni-only"\n'
            '    minimum_protocol_version       = "TLSv1.2_2021"\n'
            '  }\n'
            '  \n'
            '  restrictions {\n'
            '    geo_restriction {\n'
            '      restriction_type = "none"\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::CloudFront::Distribution\n"
            "Properties:\n"
            "  DistributionConfig:\n"
            "    Enabled: true\n"
            "    DefaultCacheBehavior:\n"
            "      ViewerProtocolPolicy: redirect-to-https\n"
            "      TargetOriginId: S3-Origin\n"
            "      ForwardedValues:\n"
            "        QueryString: false\n"
            "    ViewerCertificate:\n"
            "      AcmCertificateArn: !Ref Certificate\n"
            "      SslSupportMethod: sni-only\n"
            "      MinimumProtocolVersion: TLSv1.2_2021"
        ),
    },
    
    "msk_cluster_encryption_in_transit": {
        "cli": (
            "# Create MSK cluster with encryption (must be set at creation)\n"
            "aws kafka create-cluster \\\n"
            "  --cluster-name secure-msk \\\n"
            "  --broker-node-group-info file://broker-config.json \\\n"
            "  --encryption-info '{\n"
            "    \"EncryptionInTransit\": {\n"
            "      \"ClientBroker\": \"TLS\",\n"
            "      \"InCluster\": true\n"
            "    },\n"
            "    \"EncryptionAtRest\": {\n"
            "      \"DataVolumeKMSKeyId\": \"<KMS_KEY_ARN>\"\n"
            "    }\n"
            "  }' \\\n"
            "  --kafka-version 2.8.1"
        ),
        "terraform": (
            'resource "aws_msk_cluster" "main" {\n'
            '  cluster_name           = "secure-msk"\n'
            '  kafka_version          = "2.8.1"\n'
            '  number_of_broker_nodes = 3\n'
            '  \n'
            '  broker_node_group_info {\n'
            '    instance_type   = "kafka.m5.large"\n'
            '    client_subnets  = aws_subnet.private[*].id\n'
            '    security_groups = [aws_security_group.msk.id]\n'
            '    \n'
            '    storage_info {\n'
            '      ebs_storage_info {\n'
            '        volume_size = 100\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '  \n'
            '  encryption_info {\n'
            '    encryption_in_transit {\n'
            '      client_broker = "TLS"\n'
            '      in_cluster    = true\n'
            '    }\n'
            '    \n'
            '    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn\n'
            '  }\n'
            '  \n'
            '  logging_info {\n'
            '    broker_logs {\n'
            '      cloudwatch_logs {\n'
            '        enabled   = true\n'
            '        log_group = aws_cloudwatch_log_group.msk.name\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}'
        ),
        "cloudformation": (
            "Type: AWS::MSK::Cluster\n"
            "Properties:\n"
            "  ClusterName: secure-msk\n"
            "  KafkaVersion: 2.8.1\n"
            "  NumberOfBrokerNodes: 3\n"
            "  EncryptionInfo:\n"
            "    EncryptionInTransit:\n"
            "      ClientBroker: TLS\n"
            "      InCluster: true\n"
            "    EncryptionAtRest:\n"
            "      DataVolumeKMSKeyId: !Ref MSKKMSKey\n"
            "  BrokerNodeGroupInfo:\n"
            "    InstanceType: kafka.m5.large\n"
            "    ClientSubnets: !Ref PrivateSubnets\n"
            "    SecurityGroups:\n"
            "      - !Ref MSKSecurityGroup"
        ),
    },
}

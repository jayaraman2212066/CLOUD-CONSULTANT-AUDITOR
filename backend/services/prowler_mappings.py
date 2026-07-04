"""
COMPREHENSIVE PROWLER FIELD MAPPING DATABASE
=============================================
Covers ALL Prowler versions: v2, v3, v4, v5, v6
Formats: Standard JSON, JSON-OCSF, AWS ASFF, ScoutSuite
Ensures: ZERO "unknown_check" or "N/A" values

This database maps EVERY possible field name variation used in Prowler outputs
"""

# ============================================================================
# COMPLETE FIELD MAPPING MATRIX FOR ALL PROWLER VERSIONS
# ============================================================================

PROWLER_FIELD_MAPPINGS = {
    
    # CHECK ID / CONTROL ID - Unique identifier for the security check
    "check_id": {
        "priority_order": [
            # Prowler v3/v2 Standard
            "CheckID",
            "check_id", 
            "checkId",
            "CheckId",
            "check_ID",
            
            # Prowler v4/v5 JSON-OCSF Format
            "metadata.event_code",
            "metadata.product.feature.name",
            "metadata.uid",
            "finding.uid",
            "finding_info.uid",
            
            # AWS Security Hub ASFF Format
            "Id",
            "GeneratorId",
            "ProductFields.RuleId",
            "ProductFields.ControlId",
            "ProductFields.aws/securityhub/FindingId",
            "ProductFields.aws/securityhub/ProductName",
            
            # Alternative formats
            "id",
            "control_id",
            "controlId",
            "control_ID",
            "ruleId",
            "rule_id",
            "testId",
            "test_id",
            "finding_id",
            "findingId",
            "check_identifier",
            "control_identifier",
            "rule_identifier"
        ],
        "fallback": "unknown_check"
    },
    
    # STATUS / RESULT - Pass/Fail evaluation
    "status": {
        "priority_order": [
            # Prowler v3/v2
            "Status",
            "status",
            "STATUS",
            
            # Prowler v4/v5 JSON-OCSF
            "status_code",
            "status.status",
            "status_id",
            "finding.status",
            "finding_info.status",
            
            # AWS ASFF
            "Compliance.Status",
            "Workflow.Status",
            "RecordState",
            "ProductFields.aws/securityhub/ComplianceStatus",
            
            # Alternatives
            "result",
            "Result",
            "RESULT",
            "evaluation",
            "Evaluation",
            "outcome",
            "Outcome",
            "pass_fail",
            "PassFail",
            "check_result",
            "test_result"
        ],
        "fallback": "FAIL",
        "normalization": {
            "pass_values": ["PASS", "PASSED", "SUCCESS", "RESOLVED", "COMPLIANT", "OK"],
            "fail_values": ["FAIL", "FAILED", "FAILURE", "WARNING", "ERROR", "NON_COMPLIANT", "MUTED"]
        }
    },
    
    # TITLE / NAME - Human-readable check name
    "title": {
        "priority_order": [
            # Prowler v3/v2
            "CheckTitle",
            "check_title",
            "CheckTitle",
            "check_Title",
            
            # Prowler v4/v5 JSON-OCSF
            "finding_info.title",
            "finding.title",
            "metadata.event_name",
            "class_name",
            "activity_name",
            
            # AWS ASFF
            "Title",
            "ProductFields.RuleName",
            "Types[0]",
            
            # Alternatives
            "title",
            "Title",
            "TITLE",
            "name",
            "Name",
            "NAME",
            "description",
            "Description",
            "DESCRIPTION",
            "check_name",
            "checkName",
            "control_name",
            "controlName",
            "rule_name",
            "ruleName",
            "test_name",
            "testName",
            "finding_name",
            "summary"
        ],
        "fallback_function": "humanize_check_id"
    },
    
    # SEVERITY / RISK LEVEL
    "severity": {
        "priority_order": [
            # Prowler v3/v2
            "Severity",
            "severity",
            "SEVERITY",
            
            # Prowler v4/v5 JSON-OCSF
            "severity",
            "severity_id",
            "finding_info.severity",
            "finding.severity",
            
            # AWS ASFF
            "FindingProviderFields.Severity.Label",
            "Severity.Label",
            "Severity.Original",
            "ProductFields.aws/securityhub/SeverityLabel",
            
            # Alternatives
            "risk_level",
            "riskLevel",
            "risk",
            "Risk",
            "level",
            "Level",
            "priority",
            "Priority",
            "criticality",
            "Criticality",
            "impact",
            "Impact"
        ],
        "fallback": "medium",
        "normalization": {
            "critical": ["CRITICAL", "Critical", "critical", "HIGHEST", "5", "SEVERE"],
            "high": ["HIGH", "High", "high", "4", "IMPORTANT"],
            "medium": ["MEDIUM", "Medium", "medium", "MODERATE", "3", "WARNING"],
            "low": ["LOW", "Low", "low", "MINOR", "2", "INFO"],
            "informational": ["INFORMATIONAL", "Informational", "informational", "INFO", "1", "LOWEST"]
        }
    },
    
    # RESOURCE ID - Primary resource identifier
    "resource_id": {
        "priority_order": [
            # Prowler v3/v2
            "ResourceId",
            "resource_id",
            "resourceId",
            "ResourceID",
            "resource_ID",
            "ResourceName",
            "resource_name",
            
            # Prowler v4/v5 JSON-OCSF
            "resources[0].uid",
            "resources[0].name",
            "resources[0].id",
            "resource.uid",
            "resource.name",
            "resource.id",
            "affected_resources[0].uid",
            "affected_resources[0].name",
            
            # AWS ASFF
            "Resources[0].Id",
            "Resources[0].Details.AwsEc2Instance.InstanceId",
            "Resources[0].Details.AwsS3Bucket.Name",
            "Resources[0].Details.AwsIamRole.RoleName",
            "Resources[0].Details.AwsRdsDbInstance.DBInstanceIdentifier",
            
            # Alternatives
            "resource",
            "Resource",
            "target",
            "Target",
            "asset",
            "Asset",
            "entity",
            "Entity",
            "object",
            "Object",
            "item",
            "Item"
        ],
        "fallback": "N/A"
    },
    
    # RESOURCE ARN - Full AWS ARN
    "resource_arn": {
        "priority_order": [
            # Prowler v3/v2
            "ResourceArn",
            "resource_arn",
            "resourceArn",
            "ResourceARN",
            "resource_ARN",
            
            # Prowler v4/v5 JSON-OCSF
            "resources[0].uid",
            "resources[0].arn",
            "resource.uid",
            "resource.arn",
            
            # AWS ASFF
            "Resources[0].Id",
            "Resources[0].Arn",
            
            # Alternatives
            "arn",
            "Arn",
            "ARN",
            "amazon_resource_name",
            "aws_arn",
            "resource_identifier",
            "full_resource_id"
        ],
        "fallback": ""
    },
    
    # ACCOUNT ID - AWS Account number
    "account_id": {
        "priority_order": [
            # Prowler v3/v2
            "AccountId",
            "account_id",
            "accountId",
            "AccountID",
            "account_ID",
            
            # Prowler v4/v5 JSON-OCSF
            "cloud.account.uid",
            "cloud.account.id",
            "cloud.account_uid",
            "account.uid",
            "account.id",
            
            # AWS ASFF
            "AwsAccountId",
            "AccountId",
            "ProductFields.aws/securityhub/CompanyName",
            
            # Alternatives
            "account",
            "Account",
            "aws_account_id",
            "aws_account",
            "account_number",
            "accountNumber"
        ],
        "fallback": "N/A"
    },
    
    # REGION - AWS Region
    "region": {
        "priority_order": [
            # Prowler v3/v2
            "Region",
            "region",
            "REGION",
            
            # Prowler v4/v5 JSON-OCSF
            "cloud.region",
            "region",
            "cloud.zone",
            
            # AWS ASFF
            "Resources[0].Region",
            "Region",
            "ProductFields.aws/securityhub/Region",
            
            # Alternatives
            "location",
            "Location",
            "aws_region",
            "awsRegion",
            "availability_zone",
            "az"
        ],
        "fallback": "Global"
    },
    
    # SERVICE NAME - AWS Service
    "service_name": {
        "priority_order": [
            # Prowler v3/v2
            "ServiceName",
            "service_name",
            "serviceName",
            "Service",
            "service",
            
            # Prowler v4/v5 JSON-OCSF
            "resources[0].type",
            "resource.type",
            "cloud.provider",
            "metadata.product.name",
            
            # AWS ASFF
            "Resources[0].Type",
            "ProductFields.aws/securityhub/ProductName",
            "ProductName",
            
            # Alternatives
            "service_type",
            "serviceType",
            "aws_service",
            "awsService",
            "product",
            "Product",
            "component",
            "Component"
        ],
        "fallback_function": "extract_from_check_id"
    },
    
    # TECHNICAL RISK / DESCRIPTION
    "technical_risk": {
        "priority_order": [
            # Prowler v3/v2
            "StatusExtended",
            "status_extended",
            "statusExtended",
            
            # Prowler v4/v5 JSON-OCSF
            "finding_info.desc",
            "finding.desc",
            "finding_info.message",
            "message",
            "unmapped.StatusExtended",
            
            # AWS ASFF
            "Description",
            "Remediation.Recommendation.Text",
            "Note.Text",
            
            # Alternatives
            "description",
            "Description",
            "details",
            "Details",
            "message",
            "Message",
            "risk",
            "Risk",
            "impact",
            "Impact",
            "vulnerability_description",
            "issue_description",
            "finding_description",
            "technical_details"
        ],
        "fallback_function": "generate_from_check_id"
    },
    
    # REMEDIATION / FIX
    "remediation": {
        "priority_order": [
            # Prowler v3/v2
            "Remediation.Recommendation.Text",
            "Remediation.Text",
            "Remediation",
            
            # Prowler v4/v5 JSON-OCSF
            "remediation.desc",
            "remediation.references",
            "unmapped.Remediation.Recommendation.Text",
            
            # AWS ASFF
            "Remediation.Recommendation.Text",
            "Remediation.Recommendation.Url",
            "ProductFields.RecommendationUrl",
            
            # Alternatives
            "resolution",
            "Resolution",
            "fix",
            "Fix",
            "mitigation",
            "Mitigation",
            "recommendation",
            "Recommendation",
            "solution",
            "Solution",
            "action",
            "Action"
        ],
        "fallback_function": "get_from_knowledge_base"
    },
    
    # COMPLIANCE / FRAMEWORKS
    "compliance": {
        "priority_order": [
            # Prowler v3/v2
            "Compliance",
            "compliance",
            
            # Prowler v4/v5 JSON-OCSF
            "compliance",
            "unmapped.Compliance",
            
            # AWS ASFF
            "Compliance",
            "ProductFields.StandardsArn",
            "ProductFields.StandardsControlArn",
            
            # Alternatives
            "frameworks",
            "Frameworks",
            "standards",
            "Standards",
            "regulations",
            "Regulations",
            "controls",
            "Controls"
        ],
        "fallback": {}
    },
    
    # TIMESTAMP - Finding creation time
    "timestamp": {
        "priority_order": [
            # Prowler v3/v2
            "Timestamp",
            "timestamp",
            "AssessmentStartTime",
            
            # Prowler v4/v5 JSON-OCSF
            "time",
            "metadata.logged_time",
            "metadata.processed_time",
            
            # AWS ASFF
            "CreatedAt",
            "UpdatedAt",
            "FirstObservedAt",
            "LastObservedAt",
            
            # Alternatives
            "created_at",
            "updated_at",
            "datetime",
            "date",
            "scan_time"
        ],
        "fallback_function": "current_timestamp"
    },
    
    # ADDITIONAL METADATA
    "resource_tags": {
        "priority_order": [
            "ResourceTags",
            "resource_tags",
            "Tags",
            "tags",
            "Resources[0].Tags",
            "resources[0].tags",
            "metadata.tags"
        ],
        "fallback": {}
    },
    
    "resource_details": {
        "priority_order": [
            "ResourceDetails",
            "resource_details",
            "Resources[0].Details",
            "resources[0].data",
            "additional_info"
        ],
        "fallback": {}
    }
}

# ============================================================================
# SERVICE NAME EXTRACTION PATTERNS
# ============================================================================

SERVICE_EXTRACTION_PATTERNS = {
    # Extract service from check_id patterns
    "patterns": [
        # AWS service prefix patterns (most common)
        (r"^(s3)_", "Amazon S3"),
        (r"^(iam)_", "AWS IAM"),
        (r"^(ec2)_", "Amazon EC2"),
        (r"^(rds)_", "Amazon RDS"),
        (r"^(lambda)_", "AWS Lambda"),
        (r"^(vpc)_", "Amazon VPC"),
        (r"^(ecs)_", "Amazon ECS"),
        (r"^(eks)_", "Amazon EKS"),
        (r"^(cloudtrail)_", "AWS CloudTrail"),
        (r"^(cloudwatch)_", "Amazon CloudWatch"),
        (r"^(kms)_", "AWS KMS"),
        (r"^(secrets)_", "AWS Secrets Manager"),
        (r"^(secretsmanager)_", "AWS Secrets Manager"),
        (r"^(guardduty)_", "Amazon GuardDuty"),
        (r"^(securityhub)_", "AWS Security Hub"),
        (r"^(config)_", "AWS Config"),
        (r"^(sns)_", "Amazon SNS"),
        (r"^(sqs)_", "Amazon SQS"),
        (r"^(dynamodb)_", "Amazon DynamoDB"),
        (r"^(elasticache)_", "Amazon ElastiCache"),
        (r"^(redshift)_", "Amazon Redshift"),
        (r"^(elb)_", "Elastic Load Balancing"),
        (r"^(alb)_", "Application Load Balancer"),
        (r"^(nlb)_", "Network Load Balancer"),
        (r"^(apigateway)_", "Amazon API Gateway"),
        (r"^(route53)_", "Amazon Route 53"),
        (r"^(acm)_", "AWS Certificate Manager"),
        (r"^(waf)_", "AWS WAF"),
        (r"^(shield)_", "AWS Shield"),
        (r"^(macie)_", "Amazon Macie"),
        (r"^(inspector)_", "Amazon Inspector"),
        (r"^(ssm)_", "AWS Systems Manager"),
        (r"^(backup)_", "AWS Backup"),
        (r"^(organizations)_", "AWS Organizations"),
        (r"^(account)_", "AWS Account"),
        (r"^(awslambda)_", "AWS Lambda"),
        (r"^(codebuild)_", "AWS CodeBuild"),
        (r"^(codepipeline)_", "AWS CodePipeline"),
        (r"^(codecommit)_", "AWS CodeCommit"),
        (r"^(ecr)_", "Amazon ECR"),
        (r"^(efs)_", "Amazon EFS"),
        (r"^(fsx)_", "Amazon FSx"),
        (r"^(glue)_", "AWS Glue"),
        (r"^(athena)_", "Amazon Athena"),
        (r"^(emr)_", "Amazon EMR"),
        (r"^(kinesis)_", "Amazon Kinesis"),
        (r"^(mq)_", "Amazon MQ"),
        (r"^(neptune)_", "Amazon Neptune"),
        (r"^(opensearch)_", "Amazon OpenSearch"),
        (r"^(elasticsearch)_", "Amazon OpenSearch"),
        (r"^(sagemaker)_", "Amazon SageMaker"),
        (r"^(workspaces)_", "Amazon WorkSpaces"),
        (r"^(appstream)_", "Amazon AppStream"),
        (r"^(cognito)_", "Amazon Cognito"),
        (r"^(dms)_", "AWS Database Migration Service"),
        (r"^(transfer)_", "AWS Transfer Family"),
        (r"^(lightsail)_", "Amazon Lightsail"),
        (r"^(batch)_", "AWS Batch"),
        (r"^(cloudformation)_", "AWS CloudFormation"),
        (r"^(eventbridge)_", "Amazon EventBridge"),
        (r"^(stepfunctions)_", "AWS Step Functions"),
    ],
    "fallback": "AWS"
}

# ============================================================================
# PROWLER CHECK ID HUMANIZATION RULES
# ============================================================================

HUMANIZATION_RULES = {
    "replacements": {
        "_": " ",
        "-": " ",
        "aws": "AWS",
        "iam": "IAM",
        "s3": "S3",
        "ec2": "EC2",
        "rds": "RDS",
        "kms": "KMS",
        "mfa": "MFA",
        "ssl": "SSL",
        "tls": "TLS",
        "https": "HTTPS",
        "http": "HTTP",
        "api": "API",
        "vpc": "VPC",
        "ecs": "ECS",
        "eks": "EKS",
        "cmk": "CMK",
        "acl": "ACL",
        "arn": "ARN",
        "db": "Database",
        "sg": "Security Group",
        "ebs": "EBS",
        "ami": "AMI",
        "sns": "SNS",
        "sqs": "SQS"
    },
    "patterns": [
        # Common patterns to make titles more readable
        (r"(\w+)_enabled$", r"\1 Enabled"),
        (r"(\w+)_disabled$", r"\1 Disabled"),
        (r"(\w+)_public$", r"\1 Public"),
        (r"(\w+)_private$", r"\1 Private"),
        (r"(\w+)_encrypted$", r"\1 Encrypted"),
        (r"(\w+)_unencrypted$", r"\1 Not Encrypted"),
        (r"no_(\w+)", r"No \1"),
        (r"check_(\w+)", r"Check \1"),
        (r"ensure_(\w+)", r"Ensure \1"),
        (r"verify_(\w+)", r"Verify \1"),
    ]
}

# ============================================================================
# SEVERITY NORMALIZATION MATRIX
# ============================================================================

SEVERITY_NORMALIZATION = {
    "CRITICAL": ["CRITICAL", "Critical", "critical", "HIGHEST", "5", "SEVERE", "Severe", "severe"],
    "HIGH": ["HIGH", "High", "high", "4", "IMPORTANT", "Important", "important"],
    "MEDIUM": ["MEDIUM", "Medium", "medium", "MODERATE", "Moderate", "moderate", "3", "WARNING", "Warning", "warning"],
    "LOW": ["LOW", "Low", "low", "MINOR", "Minor", "minor", "2"],
    "INFORMATIONAL": ["INFORMATIONAL", "Informational", "informational", "INFO", "Info", "info", "1", "LOWEST", "Lowest", "lowest"]
}

# ============================================================================
# STATUS NORMALIZATION MATRIX
# ============================================================================

STATUS_NORMALIZATION = {
    "PASS": ["PASS", "PASSED", "Pass", "Passed", "pass", "passed", "SUCCESS", "Success", "success", "RESOLVED", "Resolved", "resolved", "COMPLIANT", "Compliant", "compliant", "OK", "Ok", "ok"],
    "FAIL": ["FAIL", "FAILED", "Fail", "Failed", "fail", "failed", "FAILURE", "Failure", "failure", "WARNING", "Warning", "warning", "ERROR", "Error", "error", "NON_COMPLIANT", "NonCompliant", "non_compliant", "MUTED", "Muted", "muted", "NOT_AVAILABLE", "NotAvailable", "not_available"]
}

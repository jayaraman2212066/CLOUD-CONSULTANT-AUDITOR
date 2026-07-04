"""
Cost Savings Estimator
Maps Prowler check IDs to approximate monthly AWS cost savings.
Covers idle/unused resources flagged by Prowler.
"""
from typing import List, Dict

# Monthly USD savings per affected resource instance
COST_MAP: Dict[str, Dict] = {
    # ELB / Load Balancers
    "elb_with_no_instances":              {"monthly": 18,  "label": "Idle Classic Load Balancer"},
    "elb_with_listener_without_rules":    {"monthly": 18,  "label": "Unused ELB Listener"},
    "elbv2_listener_without_rules":       {"monthly": 22,  "label": "Idle ALB Listener"},
    # EBS Volumes
    "ec2_ebs_volume_unattached":          {"monthly": 8,   "label": "Unattached EBS Volume (avg 100GB gp2)"},
    "ec2_ebs_snapshot_is_public":         {"monthly": 2,   "label": "Unnecessary Public Snapshot"},
    "ec2_ebs_old_snapshots":              {"monthly": 3,   "label": "Old EBS Snapshot (>90 days)"},
    # EC2
    "ec2_instance_older_than_specific_days": {"monthly": 60, "label": "Long-running idle EC2 instance"},
    "ec2_stopped_instance":               {"monthly": 0,   "label": "Stopped EC2 (storage cost ~$2/mo)", "override": 2},
    # RDS
    "rds_instance_no_auto_minor_version_upgrade": {"monthly": 0, "label": "RDS patch risk (indirect cost)"},
    "rds_db_instance_no_deletion_protection":     {"monthly": 0, "label": "Data loss risk (indirect cost)"},
    # S3
    "s3_bucket_no_lifecycle_configuration": {"monthly": 5, "label": "S3 objects without lifecycle policy"},
    # Lambda
    "lambda_function_url_public":          {"monthly": 1,  "label": "Lambda public URL (abuse risk)"},
    # CloudWatch / Logging
    "cloudwatch_log_group_no_retention_policy": {"monthly": 4, "label": "CloudWatch logs no retention (unbounded cost)"},
    # Elastic IPs
    "ec2_elastic_ip_unassociated":         {"monthly": 4,  "label": "Unassociated Elastic IP"},
    # NAT Gateways
    "vpc_nat_gateway_unused":              {"monthly": 35, "label": "Unused NAT Gateway"},
    # Secrets Manager
    "secretsmanager_unused_secret":        {"monthly": 0.40, "label": "Unused Secret ($0.40/secret/mo)"},
}

QUICK_WIN_CHECKS = {
    "s3_bucket_public_access_block",
    "iam_root_mfa_enabled",
    "cloudtrail_enabled",
    "guardduty_enabled",
    "ec2_elastic_ip_unassociated",
    "secretsmanager_unused_secret",
    "cloudwatch_log_group_no_retention_policy",
    "iam_password_policy_minimum_length_14",
    "s3_bucket_server_side_encryption_enabled",
    "ec2_ebs_volume_encryption",
}

ARCHITECTURAL_CHECKS = {
    "vpc_nat_gateway_unused",
    "ec2_instance_older_than_specific_days",
    "rds_instance_publicly_accessible",
    "eks_cluster_public_access_disabled",
    "ecs_task_definitions_no_environment_secrets",
    "lambda_function_vpc_enabled",
    "cloudtrail_multi_region_enabled",
    "config_enabled_all_regions",
}


def estimate_costs(findings: List[Dict]) -> Dict:
    """
    Returns cost savings breakdown and time-to-fix groupings.
    """
    total_monthly = 0.0
    cost_items = []
    quick_wins = []
    arch_risks = []
    medium_effort = []

    for f in findings:
        cid = f.get("check_id", "")
        count = max(f.get("affected_count", 1), 1)

        # Cost savings
        if cid in COST_MAP:
            entry = COST_MAP[cid]
            monthly = entry.get("override", entry["monthly"]) * count
            if monthly > 0:
                cost_items.append({
                    "check_id": cid,
                    "label":    entry["label"],
                    "count":    count,
                    "monthly":  round(monthly, 2),
                    "annual":   round(monthly * 12, 2),
                })
                total_monthly += monthly

        # Time-to-fix grouping
        if cid in QUICK_WIN_CHECKS:
            quick_wins.append(f.get("title", cid))
        elif cid in ARCHITECTURAL_CHECKS:
            arch_risks.append(f.get("title", cid))
        else:
            sev = f.get("severity", "medium")
            if sev in ("critical", "high"):
                arch_risks.append(f.get("title", cid))
            else:
                medium_effort.append(f.get("title", cid))

    cost_items.sort(key=lambda x: -x["monthly"])

    return {
        "total_monthly_savings": round(total_monthly, 2),
        "total_annual_savings":  round(total_monthly * 12, 2),
        "items":       cost_items,
        "quick_wins":  quick_wins[:20],
        "arch_risks":  arch_risks[:20],
        "medium_effort": medium_effort[:20],
        "quick_win_count":   len(quick_wins),
        "arch_risk_count":   len(arch_risks),
        "medium_effort_count": len(medium_effort),
    }

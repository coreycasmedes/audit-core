"""Pulumi program — provisions AWS CloudTrail + IAM reader for audit-core."""
import json

import pulumi
import pulumi_aws as aws

cfg = pulumi.Config()
org_name = cfg.require("org_name")
enable_cloudtrail = cfg.get("enable_cloudtrail") != "false"

caller = aws.get_caller_identity()
region = aws.get_region()

# ── CloudTrail (optional) ────────────────────────────────────────────────────

if enable_cloudtrail:
    trail_bucket = aws.s3.Bucket(
        f"{org_name}-audit-core-trail",
        bucket=f"{org_name}-audit-core-trail-{caller.account_id}",
        force_destroy=True,
    )

    aws.s3.BucketPublicAccessBlock(
        f"{org_name}-trail-block-public",
        bucket=trail_bucket.id,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    )

    trail_policy = aws.s3.BucketPolicy(
        f"{org_name}-trail-bucket-policy",
        bucket=trail_bucket.id,
        policy=pulumi.Output.all(trail_bucket.arn, caller.account_id).apply(
            lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": args[0],
                    },
                    {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"{args[0]}/AWSLogs/{args[1]}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            })
        ),
    )

    trail = aws.cloudtrail.Trail(
        f"{org_name}-audit-core",
        name=f"{org_name}-audit-core",
        s3_bucket_name=trail_bucket.id,
        include_global_service_events=True,
        is_multi_region_trail=True,
        enable_log_file_validation=True,
        opts=pulumi.ResourceOptions(depends_on=[trail_policy]),
    )
    pulumi.export("trail_arn", trail.arn)
else:
    pulumi.export("trail_arn", pulumi.Output.from_input("pre-existing"))

# ── IAM reader ───────────────────────────────────────────────────────────────

iam_user = aws.iam.User(
    f"{org_name}-audit-core-reader",
    name=f"{org_name}-audit-core-reader",
    tags={"Project": "audit-core", "Purpose": "ZK proof generation"},
)

read_policy = aws.iam.Policy(
    f"{org_name}-audit-core-read",
    name=f"{org_name}-audit-core-read",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CloudTrailRead",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:DescribeTrails",
            ],
            "Resource": "*",
        }],
    }),
)

aws.iam.UserPolicyAttachment(
    f"{org_name}-audit-core-read-attach",
    user=iam_user.name,
    policy_arn=read_policy.arn,
)

access_key = aws.iam.AccessKey(
    f"{org_name}-audit-core-key",
    user=iam_user.name,
)

pulumi.export("aws_access_key_id", access_key.id)
pulumi.export("aws_secret_access_key", pulumi.Output.secret(access_key.secret))
pulumi.export("aws_region", region.name)
pulumi.export("aws_account_id", caller.account_id)
pulumi.export("iam_user_arn", iam_user.arn)

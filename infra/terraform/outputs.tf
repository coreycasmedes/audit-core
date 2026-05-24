output "aws_access_key_id" {
  description = "Access key for the audit-core reader IAM user"
  value       = aws_iam_access_key.reader.id
}

output "aws_secret_access_key" {
  description = "Secret key written to config.env by bootstrap.sh"
  value       = aws_iam_access_key.reader.secret
  sensitive   = true
}

output "aws_region" {
  value = var.aws_region
}

output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "iam_user_arn" {
  value = aws_iam_user.reader.arn
}

output "trail_arn" {
  description = "ARN of the CloudTrail trail (empty if enable_cloudtrail=false)"
  value       = var.enable_cloudtrail ? aws_cloudtrail.audit_core[0].arn : ""
}

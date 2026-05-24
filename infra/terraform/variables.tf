variable "org_name" {
  description = "Short identifier used in resource names (e.g. \"acme\")"
  type        = string
}

variable "aws_region" {
  description = "Primary AWS region for CloudTrail and the IAM user"
  type        = string
  default     = "us-east-1"
}

variable "enable_cloudtrail" {
  description = "Create a new multi-region CloudTrail trail. Set false if your org already has one."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Extra tags applied to all resources"
  type        = map(string)
  default     = {}
}

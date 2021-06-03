package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSAWSESDomainShouldHaveAuditLogEnabled(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "check fails if any of the log options dont specify log_type of AUDIT_LOGS",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "TEST_LOGS"
  }
}
`,
			mustIncludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
		{
			name: "check passes if one of the log_type is AUDIT_LOGS and audit log is enabled",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
`,
			mustExcludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
		{
			name: "check passes if one of the log_type is AUDIT_LOGS and audit log is enabled - using dynamic block",
			source: `
resource "aws_elasticsearch_domain" "example" {
  // other config
	dynamic "log_publishing_options" {
	  for_each = ["INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS", "AUDIT_LOGS", "ES_APPLICATION_LOGS"]
	  content {
		enabled = true
		cloudwatch_log_group_arn = aws_cloudwatch_log_group.es.arn
		log_type = log_publishing_options.value
	  }
	}
}
`,
			mustExcludeResultCode: checks.AWSESDomainLoggingEnabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

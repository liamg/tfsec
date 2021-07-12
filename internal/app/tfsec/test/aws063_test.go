package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSCloudtrailEnabledInAllRegions(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Test cloudtrail not configured for multi region use",
			source: `
resource "aws_cloudtrail" "bad_example" {
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
`,
			mustIncludeResultCode: rules.AWSCloudtrailEnabledInAllRegions,
		},
		{
			name: "Test multiregion set to false fails",
			source: `
resource "aws_cloudtrail" "bad_example" {
  is_multi_region_trail = false
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
`,
			mustIncludeResultCode: rules.AWSCloudtrailEnabledInAllRegions,
		},
		{
			name: "Test multi region correctly configured",
			source: `
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
    }
  }
}
`,
			mustExcludeResultCode: rules.AWSCloudtrailEnabledInAllRegions,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

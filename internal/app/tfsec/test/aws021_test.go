package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSCloudFrontOutdatedProtocol(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no viewer_certificate block in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {

}`,
			mustIncludeResultCode: rules.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check no default minimum_protocol_version attribute in viewer_certificate block",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}`,
			mustIncludeResultCode: rules.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check TLSv1.2_2019 not used",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.2_2018"
  }
}`,
			mustIncludeResultCode: rules.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check TLS versions equal to 2021 are allowed",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.2_2021"
  }
}`,
			mustExcludeResultCode: rules.AWSCloudFrontOutdatedProtocol,
		},
		{
			name: "check TLS versions greater than 2021 are allowed",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.2_2024"
  }
}`,
			mustExcludeResultCode: rules.AWSCloudFrontOutdatedProtocol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}

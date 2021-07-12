package rules

import (
	"fmt"

	"strings"

	"strconv"

	"errors"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudFrontOutdatedProtocol = "AWS021"
const AWSCloudFrontOutdatedProtocolDescription = "CloudFront distribution uses outdated SSL/TLS protocols."
const AWSCloudFrontOutdatedProtocolImpact = "Outdated SSL policies increase exposure to known vulnerabilities"
const AWSCloudFrontOutdatedProtocolResolution = "Use the most modern TLS/SSL policies available"
const AWSCloudFrontOutdatedProtocolExplanation = `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`
const AWSCloudFrontOutdatedProtocolBadExample = `
resource "aws_cloudfront_distribution" "bad_example" {
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version = "TLSv1.0"
  }
}
`
const AWSCloudFrontOutdatedProtocolGoodExample = `
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSCloudFrontOutdatedProtocol,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSCloudFrontOutdatedProtocolDescription,
			Impact:      AWSCloudFrontOutdatedProtocolImpact,
			Resolution:  AWSCloudFrontOutdatedProtocolResolution,
			Explanation: AWSCloudFrontOutdatedProtocolExplanation,
			BadExample:  AWSCloudFrontOutdatedProtocolBadExample,
			GoodExample: AWSCloudFrontOutdatedProtocolGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Error,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context *hclcontext.Context) {

			viewerCertificateBlock := resourceBlock.GetBlock("viewer_certificate")
			minVersion := viewerCertificateBlock.GetAttribute("minimum_protocol_version")

			minBaseVersion, minCipherSupportVersion, minVersionErr := func() (string, int, error) {
				errorMessage := "Undecipherable minimum_protocol_version"
				if minVersion.Type() != cty.String {
					return "", 0, errors.New(errorMessage)
				}

				semver := strings.Split(minVersion.Value().AsString(), "_")

				if len(semver) < 2 {
					return "", 0, errors.New(errorMessage)
				}

				semverCipherSupportVersion, err := strconv.Atoi(semver[1])

				if err != nil {
					return "", 0, err
				}

				return semver[0], semverCipherSupportVersion, nil
			}()

			if viewerCertificateBlock == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing viewer_certificate block)", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			if minVersion == nil {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing minimum_protocol_version attribute)", resourceBlock.FullName())).
						WithRange(viewerCertificateBlock.Range()).
						WithSeverity(severity.Error),
				)
			} else if (minVersionErr != nil) || !(minBaseVersion == "TLSv1.2" && minCipherSupportVersion >= 2021) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLSv1.2_2021)", resourceBlock.FullName())).
						WithRange(minVersion.Range()).
						WithSeverity(severity.Error),
				)
			}
		},
	})
}

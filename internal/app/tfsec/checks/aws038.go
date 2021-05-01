package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	AWSIAMPasswordExpiry            scanner.RuleCode    = "AWS038"
	AWSIAMPasswordExpiryDescription scanner.RuleSummary = "IAM Password policy should have expiry less than or equal to 90 days."
	AWSIAMPasswordExpiryImpact                          = "Long life password increase the likelihood of a password eventually being compromised"
	AWSIAMPasswordExpiryResolution                      = "Limit the password duration with an expiry in the policy"
	AWSIAMPasswordExpiryExplanation                     = `
IAM account password policies should have a maximum age specified. 

The account password policy should be set to expire passwords after 90 days or less.
`
	AWSIAMPasswordExpiryBadExample = `
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# max_password_age not set
	# ...
}
`
	AWSIAMPasswordExpiryGoodExample = `
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	max_password_age = 90
	# ...
}
`
)

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSIAMPasswordExpiry,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSIAMPasswordExpiryDescription,
			Impact:      AWSIAMPasswordExpiryImpact,
			Resolution:  AWSIAMPasswordExpiryResolution,
			Explanation: AWSIAMPasswordExpiryExplanation,
			BadExample:  AWSIAMPasswordExpiryBadExample,
			GoodExample: AWSIAMPasswordExpiryGoodExample,
			Links: []string{
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_iam_account_password_policy"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
			if attr := block.GetAttribute("max_password_age"); attr == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not have a max password age set.", block.FullName()),
						block.Range(),
						scanner.SeverityWarning,
					),
				}
			} else if attr.Value().Type() == cty.Number {
				value, _ := attr.Value().AsBigFloat().Float64()
				if value > 90 {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has high password age.", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityWarning,
						),
					}
				}
			}
			return nil
		},
	})
}

package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_DIGFirewallHasOpenOutboundAccess(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "digital ocean firewall with open destination addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["0.0.0.0/0", "::/0"]
	}
}
`,
			mustIncludeResultCode: rules.DIGFirewallHasOpenOutboundAccess,
		},
		{
			name: "digital ocean firewall with open ipv6 destination addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["::/0"]
	}
}
`,
			mustIncludeResultCode: rules.DIGFirewallHasOpenOutboundAccess,
		},
		{
			name: "digital ocean firewall with open ipv4 destination addresses fails check",
			source: `
resource "digitalocean_firewall" "bad_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["0.0.0.0/0"]
	}
}
`,
			mustIncludeResultCode: rules.DIGFirewallHasOpenOutboundAccess,
		},
		{
			name: "digital ocean firewall with good destination addresses passes check",
			source: `
resource "digitalocean_firewall" "good_example" {
	name = "only-22-80-and-443"
  
	droplet_ids = [digitalocean_droplet.web.id]
  
	outbound_rule {
	  protocol         = "tcp"
	  port_range       = "22"
	  destination_addresses = ["192.168.1.0/24", "2002:1:2::/48"]
	}
}

`,
			mustExcludeResultCode: rules.DIGFirewallHasOpenOutboundAccess,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}

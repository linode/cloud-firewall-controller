package rules

import (
	"github.com/linode/cloud-firewall-controller/api/alpha1v1"
)

// if you need to update the default ruleset, you can do so here but copy what is currently defined as defaultRuleset
// into defaultRulesetPrevious slice.
// We use this to compare the ruleset in the controller to the ruleset in the k8s api custom resource. If the rules match
// the previous then we can safely apply the new defaults. If it does not match then we assume the user has modified the
// ruleset. In this case we will not apply the defaults and show a warning in the logs.

// Warning: order of rules matters as it controls the order of rules in the Linode Cloud Firewall and they are evaluated
// in order.

func DefaultRuleset() alpha1v1.RulesetSpec {
	return defaultRuleset
}

var defaultRuleset = alpha1v1.RulesetSpec{
	Inbound: []alpha1v1.RuleSpec{
		{
			Action:      "ACCEPT",
			Description: "ICMP Traffic",
			Label:       "allow-all-icmp",
			Protocol:    "ICMP",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"0.0.0.0/0"},
				IPv6: &[]string{"::/0"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Kubelet Health Checks",
			Label:       "allow-kubelet-health-checks",
			Protocol:    "TCP",
			Ports:       "10250,10256",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Wireguard Traffic",
			Label:       "allow-lke-wireguard",
			Protocol:    "UDP",
			Ports:       "51820",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-tcp",
			Protocol:    "TCP",
			Ports:       "53",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster DNS",
			Label:       "allow-cluster-dns-udp",
			Protocol:    "UDP",
			Ports:       "53",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Calico BGP",
			Label:       "allow-calico-bgp",
			Protocol:    "TCP",
			Ports:       "179",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Calico Typha",
			Label:       "allow-calico-typha",
			Protocol:    "TCP",
			Ports:       "5473",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-tcp",
			Protocol:    "TCP",
			Ports:       "30000-32767",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "Cluster Nodeports",
			Label:       "allow-cluster-nodeports-udp",
			Protocol:    "UDP",
			Ports:       "30000-32767",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.255.0/24"},
			},
		},
		{
			Action:      "ACCEPT",
			Description: "IPENCAP Private",
			Label:       "allow-cluster-ipencap",
			Protocol:    "IPENCAP",
			Addresses: alpha1v1.AddressSpec{
				IPv4: &[]string{"192.168.128.0/17"},
			},
		},
	},
	InboundPolicy:  "DROP",
	Outbound:       []alpha1v1.RuleSpec{},
	OutboundPolicy: "ACCEPT",
}

var defaultRulesetPrevious = []alpha1v1.RulesetSpec{
	{
		Inbound: []alpha1v1.RuleSpec{
			{
				Action:      "ACCEPT",
				Description: "ICMP Traffic",
				Label:       "allow-all-icmp",
				Protocol:    "ICMP",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"0.0.0.0/0"},
					IPv6: &[]string{"::/0"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Kubelet Health Checks",
				Label:       "allow-kubelet-health-checks",
				Protocol:    "TCP",
				Ports:       "10250,10256",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Cluster Wireguard Traffic",
				Label:       "allow-lke-wireguard",
				Protocol:    "UDP",
				Ports:       "51820",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Cluster DNS",
				Label:       "allow-cluster-dns-tcp",
				Protocol:    "TCP",
				Ports:       "53",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Cluster DNS",
				Label:       "allow-cluster-dns-udp",
				Protocol:    "UDP",
				Ports:       "53",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Calico BGP",
				Label:       "allow-calico-bgp",
				Protocol:    "TCP",
				Ports:       "179",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Cluster Nodeports",
				Label:       "allow-cluster-nodeports-tcp",
				Protocol:    "TCP",
				Ports:       "30000-32767",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.255.0/24"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "Cluster Nodeports",
				Label:       "allow-cluster-nodeports-udp",
				Protocol:    "UDP",
				Ports:       "30000-32767",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.255.0/24"},
				},
			},
			{
				Action:      "ACCEPT",
				Description: "IPENCAP Private",
				Label:       "allow-cluster-ipencap",
				Protocol:    "IPENCAP",
				Addresses: alpha1v1.AddressSpec{
					IPv4: &[]string{"192.168.128.0/17"},
				},
			},
		},
		InboundPolicy:  "DROP",
		Outbound:       []alpha1v1.RuleSpec{},
		OutboundPolicy: "ACCEPT",
	},
}

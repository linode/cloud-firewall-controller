package rules

import (
	"testing"

	"github.com/linode/cloud-firewall-controller/api/alpha1v1"
)

func TestLatestRevision(t *testing.T) {
	expected := "b4d67f20643ded4ad14eb326312a29da2b29724c15b997da0447b5cc1e8f1856"
	got := LatestRevision()
	if got != expected {
		t.Errorf("LatestRevision() = %s; want %s", got, expected)
	}
}

func TestPreviousRevisions(t *testing.T) {
	expected := []string{
		"71541101aeff16632d0487a6adb56429c3cf32251cb980cd3dfe95d671b11d3f",
		"dbb5961ab214991516af923e2b5971dcb676f5837f7693cc6512eff0bbeda9e7",
		"570433286c7785bf9f9a2424e3f41c93c3c726f06c8b5d7c24811b47cbbf25e0",
		"ac66dd2bf56678e2644481015147e10ba86b4c355d51e5d349b6d468e0a4ba29",
		"63ca9c4661f5fad5665b4fbdf937eb5c4cf95f44b1d831bc92477388d6a6c6d1",
	}

	got := PreviousRevisions()
	if len(got) != len(expected) {
		t.Errorf("PreviousRevisions() length = %d; want %d", len(got), len(expected))
		return
	}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("PreviousRevisions()[%d] = %s; want %s", i, v, expected[i])
		}
	}
}

func TestSha256Hash(t *testing.T) {
	ruleset := alpha1v1.RulesetSpec{
		Inbound: []alpha1v1.RuleSpec{
			{Action: "ACCEPT", Protocol: "TCP", Ports: "80"},
		},
	}
	expected := "fd18f40d2b53e709bb220d1456aa0a1110b89ce879b79a8e5812d846395f0dbc"
	got := Sha256Hash(ruleset)
	if got != expected {
		t.Errorf("Sha256Hash() = %s; want %s", got, expected)
	}
}

func TestSha256Hash_EmptyRuleset(t *testing.T) {
	ruleset := alpha1v1.RulesetSpec{}
	expected := "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
	got := Sha256Hash(ruleset)
	if got != expected {
		t.Errorf("TestSha256Hash_EmptyRuleset() = %s; want %s", got, expected)
	}
}

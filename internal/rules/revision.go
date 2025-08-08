package rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/linode/cloud-firewall-controller/api/alpha1v1"
	"k8s.io/klog/v2"
)

func LatestRevision() string {
	return Sha256Hash(defaultRuleset)
}

func PreviousRevisions() []string {
	revisions := make([]string, 0, len(defaultRulesetPrevious))
	for _, ruleset := range defaultRulesetPrevious {
		hash := Sha256Hash(ruleset)
		if hash != "" {
			revisions = append(revisions, hash)
		}
	}
	return revisions
}

func Sha256Hash(ruleset alpha1v1.RulesetSpec) string {

	hash := sha256.New()
	if err := json.NewEncoder(hash).Encode(ruleset); err != nil {
		klog.Warningf("failed to encode ruleset - %s", err.Error())
		return ""
	}

	rulesetHash := fmt.Sprintf("%x", hash.Sum(nil))

	klog.V(5).Infof("ruleset hash: %s", rulesetHash)

	return rulesetHash
}

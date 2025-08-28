# cloud-firewall-controller

Controller for applying Cloud Firewall policies to an LKE cluster. The intention is to use this to provide a strong
default security boundary for an LKE cluster with the option to apply custom firewall rules as needed. The controller
will ensure that all nodes in the cluster are added to the same firewall ruleset.

## Upgrade from version <1.6 to 1.6+
If you are using the default firewall created by the controller you will need to add the following ports
to your current configuration in order for LKE to fully function as intended.

```
    - action: ACCEPT
      addresses:
        ipv4:
        - 192.168.128.0/17
      description: Calico Typha Access 
      label: allow-calico-typha
      ports: 5473
      protocol: TCP
    - action: ACCEPT
      addresses:
        ipv4:
        - 192.168.128.0/17
      description: Prometheus Health Check
      label: allow-prometheus-healthcheck
      ports: 9098
      protocol: TCP
```


## Installation

### Dependencies

The installation process will require the following command line tools be available on your system.

- [helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)

Installation via [helm](https://helm.sh/docs/intro/install/) can be achieved in two ways, either through checking out
the appropriate code version locally, or through the helm repository. Either option will result in the same objects
being installed into the appropriate locations in an LKE cluster.

#### Local Checkout

```sh
git clone git@github.com:linode/cloud-firewall-controller.git
cd cloud-firewall-controller 
# (optional) git checkout <tag> 

export KUBECONFIG=<kubeconfig-path> 
helm upgrade --install cloud-firewall-crd helm/crd \
&& kubectl wait --for condition=established --timeout=60s crd/cloudfirewalls.networking.linode.com \
&& helm upgrade --install cloud-firewall helm/controller
```
  
#### Helm Repo

Note that the version in the helm commands is the helm chart version, not the application version.

##### Add the cloud-firewall-controller repo

```sh
helm repo add linode-cfw https://linode.github.io/cloud-firewall-controller
helm repo update linode-cfw
```

##### Install the CRDs and Controller

```sh
export KUBECONFIG=<kubeconfig-path> 
helm install cloud-firewall-crd linode-cfw/cloud-firewall-crd \
&& kubectl wait --for condition=established --timeout=60s crd/cloudfirewalls.networking.linode.com \
&& helm install cloud-firewall linode-cfw/cloud-firewall-controller
```

##### Uninstall

```sh
export KUBECONFIG=<kubeconfig-path> 
helm delete cloud-firewall
helm delete cloud-firewall-crd
```

## Results

The output from the controller is pretty straight forward, it will generate a Cloud Firewall with a label matching the
pattern `lke-<cluster-id>` and have the following policies:
![image](./docs/images/default-result.png)

## Upgrades

Upgrading the cloud-firewall-controller version will apply the latest ruleset to the primary CloudFirewall custom resource
 if the rules detected match one of the previous revisions from this repo.

As of this release, a new field `spec.defaultRules` (default true) controls whether the built-in default rule set is
automatically applied. Your CR can be minimal and rely on defaults, and optionally specify custom rules that will be
appended after the defaults. Existing CRs that matched a known previous default ruleset will be migrated to this model
automatically by the controller.

If custom rules have been applied via the `firewall` block in the values file, these will be applied by the controller
in addition to the defaults.

```yaml
# Additional Cloud Firewall rules can be added to the default set by adding them to the list below.
# These will be applied along with the default ruleset. Any rule added here will be
# applied to all nodes in the cluster.
firewall:
  inbound:
    - label:       "allow-custom-port"
      action:      "ACCEPT"
      description: "custom-rule"
      protocol:    "TCP"
      ports:       "9999"
      addresses:
        ipv4:
          - "192.168.128.0/17"
```

Any ruleset customized outside of Helm (e.g., using kubectl) will need to be manually updated.

If we cannot automatically update the ruleset, you will see the following warning in the logs:

> [!WARNING]
> CloudFirewall object ruleset does not match latest or previous revisions. Cannot upgrade custom ruleset

If you had previously added custom rules to the CloudFirewall object in your cluster you will need to patch the
existing object after installing the CRD and controller updates. This can be accomplished by creating a patch file
which contains only your custom rules.

#### patch.json
```json
[
  {
    "op": "replace",
    "path": "/spec/ruleset",
    "value": {
      "inbound": [
        {
          "action": "ACCEPT",
          "addresses": {
            "ipv4": [
              "192.168.128.0/17"
            ]
          },
          "description": "Custom Rule",
          "label": "allow-custom",
          "ports": "9999",
          "protocol": "TCP"
        }
      ]
    }
  }
]
```

The patch can then be applied, which will allow the controller to properly import your rules and merge them with
the most up-to-date defaults. This will avoid having to apply manual changes in the future.

```bash
kubectl --kubeconfig <kubeconfig> patch cloudfirewalls -n kube-system primary --type=json --patch-f
ile patch.json
```

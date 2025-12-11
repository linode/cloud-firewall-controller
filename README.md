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

### Authentication & API Token Configuration

This controller requires a Linode API token to manage firewalls. There are two ways to provide this token:

1. Using values.yaml (Recommended)
	* Set apiToken in values.yaml:
        ```yaml
        apiToken: "<your-linode-api-token>"
        ```

    * This token will be stored in a Kubernetes Secret in the same namespace as the service account.
2. Using a Pre-existing Secret
	* If apiToken is not set in `values.yaml`, the controller will look for a Kubernetes Secret named `linode` in the `kube-system` namespace:
    ```sh
    kubectl create secret generic linode -n kube-system --from-literal=token="<your-linode-api-token>"
    ```
Required Linode API Permissions
* For Cloud Firewall (CloudFirewall CRD):
    * Requires Read/Write permissions for Firewalls.
* For NodeBalancer Firewall (NodeBalancerFirewall CRD):
    * Requires Read permissions for NodeBalancers.
    * Requires Read/Write permissions for Firewalls.

#### Local Checkout

```sh
git clone git@github.com:linode/cloud-firewall-controller.git
cd cloud-firewall-controller 
# (optional) git checkout <tag> 

export KUBECONFIG=<kubeconfig-path> 
helm upgrade --install cloud-firewall-crd helm/crd \
&& kubectl wait --for condition=established --timeout=60s crd/cloudfirewalls.networking.linode.com crd/nodebalancerfirewalls.networking.linode.com \
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

## Custom Firewall Rules

The controller supports NodeBalancer Firewalls (NodeBalancerFirewall CRD) with custom inbound/outbound rules.

Example values.yaml configuration:
```yaml
nodebalancer_firewall:
  outbound: []
  inbound: 
    - label:       "allow-http-port"
      action:      "ACCEPT"
      description: "http-rule"
      protocol:    "TCP"
      ports:       "80"
      addresses:
        ipv4:
        - "123.123.123.123/32"
    - label:       "allow-https-port"
      action:      "ACCEPT"
      description: "https-rule"
      protocol:    "TCP"
      ports:       "443"
      addresses:
        ipv4:
        - "123.123.123.123/32"
```

### Why Use NodeBalancer Firewalls?
* Without a NodeBalancerFirewall, all incoming traffic to an LKE Ingress (LoadBalancer service) is allowed by default.
* This firewall allows custom inbound/outbound rules to control traffic before it reaches the cluster.

## Results

The output from the controller is pretty straight forward, it will generate a Cloud Firewall with a label matching the
pattern `lke-<cluster-id>` and have the following policies:
![image](./docs/images/default-result.png)

## Upgrades

Upgrading the cloud-firewall-controller version will apply the latest ruleset to the primary CloudFirewall custom resource
 if the rules detected match one of the previous revisions from this repo.

As of `v0.2.0`, a new field `spec.defaultRules` (default true) controls whether the built-in default rule set is
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


### Upgrading Custom Rules
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


### Addressing Helm Errors
When upgrading with helm you may encounter the following error:
> Error: UPGRADE FAILED: Unable to continue with update: CloudFirewall "primary" in namespace "kube-system" exists and cannot be imported into the current release: invalid ownership metadata; label validation error: missing key "app.kubernetes.io/managed-by": must be set to "Helm"; annotation validation error: missing key "meta.helm.sh/release-name": must be set to "cloud-firewall-ctrl"; annotation validation error: missing key "meta.helm.sh/release-namespace": must be set to "default"

This is caused by previous versions of the controller creating the default firewall, which is not owned by helm.
To resolve the issue simply update the labels and annotations of the CloudFirewall object to match your helm release.
This can be done either through kubectl label/annotate commands or a patch.

```bash
kubectl label -n kube-system cloudfirewall/primary app.kubernetes.io/managed-by=Helm
kubectl annotate -n kube-system cloudfirewall/primary meta.helm.sh/release-name=<release-name> meta.helm.sh/release-namespace=<release-namespace>
```

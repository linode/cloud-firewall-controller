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

## Using an existing firewall (e.g. one attached by an LKE node pool)

By default the controller creates its own firewall and attaches every node to it. That
conflicts with a firewall you already attach another way, most commonly the `firewall_id`
of an LKE node pool (set through the Linode API, the Cloud Manager, or the Terraform
`linode_lke_node_pool` resource), because LKE attaches that firewall to every node the pool
creates.

Set `spec.firewall-id` to manage that firewall instead. `defaultRules` must then be set
explicitly, because importing replaces the firewall's rules:

```yaml
apiVersion: networking.linode.com/alpha1v1
kind: CloudFirewall
metadata:
  name: primary
  namespace: kube-system
spec:
  firewall-id: "123456"
  defaultRules: false
  ruleset:
    inbound: [...]   # every rule the firewall needs
```

or through the chart, which also turns off auto-creation of an empty default object
(`--auto-create-default=false`) so it cannot create a second firewall first:

```yaml
firewall:
  firewallID: "123456"
  defaultRules: false
  inbound: [...]
```

With `firewall-id` set, the controller:

- reconciles the firewall's **rules** to the default ruleset (if `defaultRules: true`) plus
  `spec.ruleset`, **replacing all of the firewall's existing rules**: inbound, outbound and
  both policies;
- does **not** create a firewall, and does not recreate the firewall if it is deleted
  (the reconcile reports an error instead);
- does **not** add or remove devices, so attachment stays with the node pool;
- does **not** delete the firewall, and puts no finalizer on the object, so deleting the
  object or uninstalling the controller leaves the firewall as it is.

> [!WARNING]
> The built-in defaults are written for a standard LKE cluster. If the firewall you import
> carries rules your cluster depends on (for example VPC rules on an LKE Enterprise cluster),
> set `defaultRules: false` and list every rule you need in `spec.ruleset.inbound`, or those
> rules are removed on the first reconcile. An empty inbound ruleset under the `DROP` policy
> would cut the nodes off, so `defaultRules: false` without inbound rules is rejected.

Progress and problems are reported as conditions on the object (`kubectl get cloudfirewall -o yaml`)
and as Events:

- `Imported`: `True` once the firewall is adopted; `False` with the reason (refused, not found,
  invalid spec) otherwise.
- `NodesProtected`: `False` when a node is not attached to the imported firewall and so is not
  protected by it.

The controller refuses to import a firewall that is attached to any device outside this
cluster: another cluster's node pool, a standalone Linode, or a NodeBalancer. Importing
replaces the firewall's whole ruleset, so those devices would get this cluster's rules, and a
firewall shared by two clusters would be overwritten by each cluster's controller in turn. Use a
separate firewall per cluster. A Linode that belongs to this LKE cluster but has not registered
as a Node yet is not treated as foreign.

Changing `firewall-id` on an existing object:

- **Adding it** to an object whose firewall the controller created applies the rules to the
  imported firewall, moves each node onto it (one detach and attach at a time, since a Linode
  can only be on one Cloud Firewall), and then deletes the old firewall.
- **Changing it** to another ID adopts the new firewall and leaves the previous one in place.
- **Removing it** releases the imported firewall exactly as it is (rules and devices untouched,
  never deleted). The controller then creates and attaches its own firewall as for a new object,
  which fails while a node pool still attaches a firewall to the nodes, so detach that first.

The controller only ever deletes, or manages the devices of, a firewall it created: one
labelled `lke-<cluster-id>` that is not recorded as imported. It records the adopted firewall in
the `networking.linode.com/imported-firewall-id` annotation (do not edit it), which lives in
metadata so that a CRD older than the controller cannot drop it. Losing the annotation can never
get a firewall deleted, because deletion requires the firewall to carry the controller's label.

With a CRD older than this change, `defaultRules` is defaulted to `true` at admission, so the
explicit-choice check cannot apply there; upgrade the CRD chart, or set `defaultRules` in the
controller chart, which enforces it.

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

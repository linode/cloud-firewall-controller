# cloud-firewall-controller
Controller for applying Cloud Firewall policies to an LKE cluster. The intention is to use this to provide a strong default security boundary for an LKE cluster with options apply custom firewall rules as needed. The controller will ensure that all nodes in the cluster are added to the same firewall ruleset.

## Installation
### Dependecies
The installation process will require the following command line tools be available on your system.
 - [helm](https://helm.sh/docs/intro/install/)
 - [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)

Installation via [helm](https://helm.sh/docs/intro/install/) can be achieved in two ways, either through checking out the appropriate code version locally, or through the helm repository. Either option will result in the same objects being installed into the appropriate locations in an LKE cluster.

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
&& helm install cloud-firewall-ctrl linode-cfw/cloud-firewall-controller
```

##### Uninstall
```sh
export KUBECONFIG=<kubeconfig-path> 
helm delete cloud-firewall-controller
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
The output from the controller is pretty striaghtforward, it will generate a Cloud Firewall with a label matching the pattern `lke-<cluster-id>` and have the following policies:
![image](./docs/images/default-result.png)

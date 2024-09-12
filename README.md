# cloud-firewall-controller
Controller for minimum cluster Cloud Firewall policies. The intention is to use this to setup the minimum security boundary for an LKE cluster.

## Installation
### Helm
Installation via helm can be achieved in two ways, either through the helm directory checked out at the appropriate tag or githash, or through a helm repository. Either option will result in the same objects being installed into the appropriate locations in an LKE cluster.

#### Directory Option
```sh
git clone git@bits.linode.com:hwagner/cloud-firewall-controller.git
cd cloud-firewall-controller
git checkout v0.1.0
KUBECONFIG=<kubeconfig-path> helm upgrade --install cloud-firewall helm/
```
  
#### Helm Repo
```sh
helm pull oci://registry-1.docker.io/hwagner/cloud-firewall-controller --version 0.1.0
KUBECONFIG=<kubeconfig path> helm upgrade --install cloud-firewall ./cloud-firewall-controller-0.1.0.tgz
```

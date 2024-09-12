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

## Results
The output from the controller is pretty striaghtforward, it will generate a Cloud Firewall with a label matching the pattern `lke-<cluster-id>` and have the following policies:
![image](https://bits.linode.com/storage/user/911/files/84cd7bc2-51cd-44ed-975a-375165e42854)

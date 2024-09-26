# cloud-firewall-controller
Controller for minimum cluster Cloud Firewall policies. The intention is to use this to setup the minimum security boundary for an LKE cluster.

## Installation
### Dependecies
The installation process will require the following command line tools be available on your system.
 - [helm](https://helm.sh/docs/intro/install/)
 - [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)

Installation via [helm](https://helm.sh/docs/intro/install/) can be achieved in two ways, either through checking out the appropriate code version locally, or through the helm repository. Either option will result in the same objects being installed into the appropriate locations in an LKE cluster.

#### Local Checkout
```sh
git clone git@bits.linode.com:hwagner/cloud-firewall-controller.git
cd cloud-firewall-controller 
# (optional) git checkout <tag> 

export KUBECONFIG=<kubeconfig-path> 
helm upgrade --install cloud-firewall-crd helm/crd \
&& kubectl wait --for condition=established --timeout=60s crd/cloudfirewalls.networking.linode.com \
&& helm upgrade --install cloud-firewall helm/controller
```
  
#### Helm Repo
Note that the version in the helm commands is the helm chart version, not the application version.
```sh
helm pull oci://registry-1.docker.io/hwagner/cloud-firewall-crd --version 0.1.0
helm pull oci://registry-1.docker.io/hwagner/cloud-firewall-controller --version 0.1.0
KUBECONFIG=<kubeconfig path> helm upgrade --install cloud-firewall-crd ./cloud-firewall-crd-0.1.0.tgz
KUBECONFIG=<kubeconfig path> helm upgrade --install cloud-firewall ./cloud-firewall-controller-0.1.0.tgz
```

## Results
The output from the controller is pretty striaghtforward, it will generate a Cloud Firewall with a label matching the pattern `lke-<cluster-id>` and have the following policies:
![image](https://bits.linode.com/storage/user/911/files/84cd7bc2-51cd-44ed-975a-375165e42854)

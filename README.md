# aBuildaKubernetes
Deploy a [MultiNode] Kubernetes Cluster. Mostly work in progress.
=======================================================================
### TODO: 
 - [ ] deploy nodes as a control plane or worker node only. 
 - [ ] add argument parsing for running sections (i.e. script building sources everytime).
 - [ ] Try to make things system independent, mostly requires systemd currently.
 - [ ] Avoid requiring root (i.e. using sudo). Currently script run as root, and requires root on each host. 

Project for building a multinode kubernetes cluster, using locally built Certificate Authorities and locally built binaries. Configuration is copied to each hosts defined in `config.yaml`. 
=======================================================================
# Scripts
The process is broken down into multiple scripts.
* proc.sh
 - The main process, setups some configuration and templates values, runs the other scripts for building out the services and certificates. 
* source-builder.sh
 - Clones and build the source repos on the hosts defined in hosts.yaml
* cert-manager.sh
 - Creates the certificate authorities and required certs for the hosts, certs defined in certs.yaml.
* setup-sources.sh
 - Configures the sources on each host. 
* common.sh
 - Common Values and functions.
=======================================================================
# Configuration 
  Configuration is handled with `config.yaml` and `certs.yaml`
* config.yaml
  - Define the hosts that will be deployed and configured
    -- To avoid ssh password authentication copy the public key for the host that will run the script to each additional host.  
  -  Define a VRRP VIP and service and cluster CIDR(s)
  - Defines where to build sources and CA(s).
  - Defines where to install kube configuration and service files. 
* certs.yaml
  - Defines the certs that will be created for the kubernetes cluster. Host based certs will be generated based on the hosts.yaml which is autogenerated. 
* hosts.yaml
  - Autogenerated from hosts defined in `config.yaml`
Autogenerated file
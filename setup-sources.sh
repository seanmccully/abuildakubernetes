#!/usr/bin/env bash
#
#MIT License
# ... (License text omitted for brevity) ...
#
# Doc:
#   Configures ETCD, Kubernetes services services and service configurations for multi node cluster.
#

_path=$(dirname "$0")
MESSAGE_HEADER="setup-sources";
source "${_path}/common.sh";

function setup_start_containerd() {
    info "starting setup_start_containerd"

    local ctd_config="/etc/containerd/config.toml";

    if [ ! -x "/usr/local/bin/containerd" ]; then
      warning "containerd binary not found, skipping configuration."
      return
    fi

    mkdir -p "$(dirname "$ctd_config")"

    exec_c "/usr/local/bin/containerd config default > ${ctd_config}"

    # Ensure version is set to 2 (Handles both version=3 and other potential values)
    exec_c "sed -i 's/version = .*/version = 2/' ${ctd_config}"

    # Configure runc runtime with SystemdCgroup
    # Use tee -a for appending configuration safely, avoiding potential issues with cat >> redirection in strict mode.
    tee -a "$ctd_config" > /dev/null <<- EOF
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
          SystemdCgroup = true
          BinaryName = "/usr/local/bin/runc"
EOF

    if [ -n "$SYSTEMCTL" ]; then
      exec_c "${SYSTEMCTL} daemon-reload"
      exec_c "${SYSTEMCTL} enable containerd"
      exec_c "${SYSTEMCTL} restart containerd"
    fi
}

function setup_etcd_conf() {
    info "starting setup_etcd_conf"
    mkdir -p "$ETCD_CONF";
    local etcd_yml="${ETCD_CONF}/etcd.conf.yml";
    local etcd_service_sample="${SRC_DIR}/etcd/contrib/systemd/etcd.service"
    local etcd_service_file="${SYSTEMD_SERVICE_PATH}/etcd.service";
    local etcd_sysusers_src="${SRC_DIR}/etcd/contrib/systemd/sysusers.d/20-etcd.conf"

    # Check if sample files exist
    if [ -f "${SRC_DIR}/etcd/etcd.conf.yml.sample" ]; then
      exec_c "install -m644 ${SRC_DIR}/etcd/etcd.conf.yml.sample ${etcd_yml}"
    else
      warning "etcd sample config not found, creating empty file."
      touch "$etcd_yml"
    fi

    if [ -f "$etcd_service_sample" ]; then
      exec_c "install -m644 ${etcd_service_sample} ${etcd_service_file}"
      exec_c "sed -i \"s~/usr/bin/etcd~/usr/local/bin/etcd --config-file ${etcd_yml}~g\" ${etcd_service_file}"
    fi

    if [ -f "$etcd_sysusers_src" ] && [ -n "$SYSTEMD_SYSUSERS" ]; then
      exec_c "install -m644 ${etcd_sysusers_src} ${SYSUSERS_DIR}/etcd.conf "
      exec_c "${SYSTEMD_SYSUSERS}"
    fi

    local hostname
    hostname=$(hostname);

    # Ensure data directory is clean and has correct permissions
    exec_c "rm -rf ${ETCD_DATA_DIR}"
    # Combined install commands
    exec_c "install -d -m 0700 -o etcd -g etcd ${ETCD_DATA_DIR} "

    if [ ! -f "$ETCD_TOKEN_FILE" ]; then
        error_message "ETCD token file not found: ${ETCD_TOKEN_FILE}" 1
        return 1
    fi
    local cluster_token
    cluster_token=$(cat "$ETCD_TOKEN_FILE");

    if [ ${#peer_ips[@]} -eq 0 ]; then
      error_message "peer_ips array is empty, cannot configure etcd." 1
      return 1
    fi

    local peer_urls="https://${peer_ips[$hostname]}:2380";
    local client_urls="https://${peer_ips[$hostname]}:2379";

    local cluster="";
    for host in "${!peer_ips[@]}"; do
        cluster+="$host=https://${peer_ips[$host]}:2380,";
    done
    cluster=${cluster::-1};

    # Use $YQ -i (in-place) instead of -ir
    $YQ -i ".name=\"${hostname}\"" "$etcd_yml";
    $YQ -i ".data-dir=\"${ETCD_DATA_DIR}\"" "$etcd_yml";
    $YQ -i ".wal-dir=\"${ETCD_DATA_DIR}/wal\"" "$etcd_yml";
    $YQ -i ".listen-peer-urls=\"${peer_urls}\"" "$etcd_yml";
    $YQ -i ".listen-client-urls=\"${client_urls},https://127.0.0.1:2379\"" "$etcd_yml";
    $YQ -i ".initial-advertise-peer-urls=\"${peer_urls}\"" "$etcd_yml";
    $YQ -i ".advertise-client-urls=\"${client_urls}\"" "$etcd_yml";
    $YQ -i ".initial-cluster=\"${cluster}\"" "$etcd_yml";
    $YQ -i ".initial-cluster-token=\"${cluster_token}\"" "$etcd_yml";
    $YQ -i ".initial-cluster-state=\"new\"" "$etcd_yml";
    $YQ -i ".log-level=\"info\"" "$etcd_yml";

    # Configure TLS (Assuming certs are installed in ETCD_PKI by proc.sh)
    $YQ -i ".client-transport-security.cert-file=\"$ETCD_PKI/server.crt\"" "$etcd_yml";
    $YQ -i ".client-transport-security.key-file=\"$ETCD_PKI/server.key\"" "$etcd_yml";
    $YQ -i ".client-transport-security.trusted-ca-file=\"$ETCD_PKI/ca.crt\"" "$etcd_yml";
    $YQ -i ".client-transport-security.client-cert-auth=true" "$etcd_yml";

    $YQ -i ".peer-transport-security.cert-file=\"$ETCD_PKI/peer.crt\"" "$etcd_yml";
    $YQ -i ".peer-transport-security.key-file=\"$ETCD_PKI/peer.key\"" "$etcd_yml";
    $YQ -i ".peer-transport-security.trusted-ca-file=\"$ETCD_PKI/ca.crt\"" "$etcd_yml";
    $YQ -i ".peer-transport-security.client-cert-auth=true" "$etcd_yml";

    info "finished setup_etcd_conf"
}

# Removed unused/incomplete function configure_apiserver

function setup_kube_apiserver() {
    info "starting setup_kube_apiserver"
    local api_env="${KUBE_DIR}/kube-apiserver.env";

    if [ ! -f "$api_env" ]; then
      warning "kube-apiserver.env not found at ${api_env}, skipping configuration."
      return
    fi

    local hostname
    hostname=$(hostname);
    local fqdn
    fqdn=$(hostname -f);
    local domain=${fqdn#*.};

    if [ ${#peer_ips[@]} -eq 0 ]; then
      error_message "peer_ips array is empty." 1
      return 1
    fi
    local bind_ip="${peer_ips[$hostname]}";

    # CLUSTER_IP is globally defined in common.sh

    local service_cert="${KUBE_PKI}/sa.pub";
    local service_key="${KUBE_PKI}/sa.key";

    # Perform substitutions
    $SED -i "s/CLUSTER_IP/${CLUSTER_IP}/g" "$api_env";
    $SED -i "s/IP_ADDR/${bind_ip}/g" "$api_env";
    $SED -i "s~SERVICE_CIDR~${SERVICE_CIDR}~g" "$api_env";
    $SED -i "s~SERVICE_PKI~${service_cert}~g" "$api_env";
    $SED -i "s~SERVICE_KEY~${service_key}~g" "$api_env";
    $SED -i "s/DOMAIN_NAME/${domain}/g" "$api_env";
    $SED -i "s~PROXY_CA_CERT~${KUBE_PKI}/front-proxy-ca.crt~g" "$api_env";
    $SED -i "s~PROXY_CERT~${KUBE_PKI}/front-proxy-client.crt~g" "$api_env";
    $SED -i "s~PROXY_KEY~${KUBE_PKI}/front-proxy-client.key~g" "$api_env";
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" "$api_env";
    $SED -i "s~API_CERT~${KUBE_PKI}/apiserver.crt~g" "$api_env";
    $SED -i "s~API_KEY~${KUBE_PKI}/apiserver.key~g" "$api_env";
    $SED -i "s~KUBELET_CLIENT_CERT~${KUBE_PKI}/apiserver-kubelet-client.crt~g" "$api_env";
    $SED -i "s~KUBELET_CLIENT_KEY~${KUBE_PKI}/apiserver-kubelet-client.key~g" "$api_env";
    $SED -i "s~ETCD_CA~${ETCD_PKI}/ca.crt~g" "$api_env";
    # Assuming apiserver-etcd-client certs are installed in KUBE_PKI
    $SED -i "s~ETCD_CERT~${KUBE_PKI}/apiserver-etcd-client.crt~g" "$api_env";
    $SED -i "s~ETCD_KEY~${KUBE_PKI}/apiserver-etcd-client.key~g" "$api_env";

    # CRITICAL FIX: Execute the function using $() to get the cluster IPs string
    local cluster
    cluster=$(etcd_cluster_ips);

    $SED -i "s~ETCD_SERVERS~${cluster}~g" "$api_env";
    info "finished setup_kube_apiserver"
}

# Removed prepare_calico_manifests as it is handled more robustly in proc.sh (provision_calico) and contained redundancies.

function setup_kube_controller_manager() {
    info "starting setup_kube_controller_manager"
    local cm_env="${KUBE_DIR}/kube-controller-manager.env";

    if [ ! -f "$cm_env" ]; then
      warning "kube-controller-manager.env not found."
      return
    fi

    # CLUSTER_IP is globally defined.
    local service_key="${KUBE_PKI}/sa.key";

    $SED -i "s~CLUSTER_ADDR~https://${CLUSTER_IP}:6443~g" "$cm_env";
    $SED -i "s~KUBECONFIG~${KUBE_DIR}/kube-controller-manager.kubeconfig~g" "$cm_env";
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" "$cm_env";
    $SED -i "s~PROXY_CA~${KUBE_PKI}/front-proxy-ca.crt~g" "$cm_env";
    $SED -i "s~SERVICE_KEY~${service_key}~g" "$cm_env";
    $SED -i "s~CA_KEY~${KUBE_PKI}/ca.key~g" "$cm_env";
    $SED -i "s~CLUSTER_CIDR~${CLUSTER_CIDR}~g" "$cm_env";
    $SED -i "s~SERVICE_CIDR~${SERVICE_CIDR}~g" "$cm_env";

    info "finished setup_kube_controller_manager"
}

function setup_kube_scheduler() {
    info "starting setup_kube_scheduler"
    local ks_env="${KUBE_DIR}/kube-scheduler.env";
    local ks_conf="${KUBE_DIR}/kube-scheduler.kubeconfig";
    local ks_yaml="${KUBE_DIR}/kube-scheduler.yaml";

    if [ ! -f "$ks_env" ] || [ ! -f "$ks_yaml" ]; then
      warning "kube-scheduler configuration files not found."
      return
    fi

    # CLUSTER_IP is globally defined.
    $SED -i "s~CLUSTER_ADDR~https://${CLUSTER_IP}:6443~g" "$ks_env";
    $SED -i "s~CONFIG_YAML~${ks_yaml}~g" "$ks_env";

    $YQ -i ".clientConnection.kubeconfig=\"${ks_conf}\"" "$ks_yaml";

    info "finished setup_kube_scheduler"
}

function setup_kubelet() {
    info "starting setup_kubelet"
    local k_env="${KUBE_DIR}/kubelet.env";
    local kubelet_dir
    kubelet_dir=$($YQ -r '.kubeletDir' "$config_yaml");
    local cluster_domain
    cluster_domain=$($YQ -r '.cluster-domain' "$config_yaml");
    local kubelet_config="${kubelet_dir}/kubelet-config.yaml";

    mkdir -p "$kubelet_dir";

    if [ ! -f "$k_env" ] || [ ! -f "$kubelet_config" ]; then
      warning "kubelet configuration files not found in ${KUBE_DIR} or ${kubelet_dir}."
      return
    fi

    local hostname
    hostname=$(hostname);
    local ip_addr="${peer_ips[$hostname]}";

    # Calculate DNS IP robustly using python (e.g., the 10th IP in the service CIDR)
    local dns_ip
    dns_ip=$(${python} -c "import ipaddress;print(list(ipaddress.IPv4Network('${SERVICE_CIDR}'))[10])")

    $SED -i "s/IP_ADDR/${ip_addr}/g" "$kubelet_config";
    $SED -i "s~KUBELET_DIR~${kubelet_dir}~g" "$kubelet_config";
    $SED -i "s/CLUSTER_DOMAIN/${cluster_domain}/g" "$kubelet_config";
    $SED -i "s/CLUSTER_DNS/${dns_ip}/g" "$kubelet_config";

    # Detect containerd socket, with fallback
    local containerd_sock
    containerd_sock=$(ss -lnp 2>/dev/null | grep 'containerd.sock' | grep -v 'ttrpc' | awk '{print $5 }' | head -n 1 || true);
    if [ -z "$containerd_sock" ]; then
      containerd_sock="/run/containerd/containerd.sock"
      warning "Could not detect running containerd socket, falling back to $containerd_sock"
    fi

    # CLUSTER_IP is globally defined.
    $SED -i "s~CLUSTER_ADDR~https://${CLUSTER_IP}:6443~g" "$k_env";
    $SED -i "s~KUBECONFIG~${kubelet_dir}/kubeconfig~g" "$k_env";
    $SED -i "s~CONTAINERD_SOCK~${containerd_sock}~g" "$k_env";
    $SED -i "s~KUBELET_CONFIG~${kubelet_config}~g" "$k_env";
    $SED -i "s/IP_ADDR/${ip_addr}/g" "$k_env";
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" "$k_env";
    info "finished setup_kubelet"
}

function setup_kube_proxy() {
    info "starting setup_kube_proxy"
    local kp_env="${KUBE_DIR}/kube-proxy.env";
    local kube_proxy_dir
    kube_proxy_dir=$($YQ -r '.kubeProxyDir' "$config_yaml");

    local kube_proxy_config="${kube_proxy_dir}/kube-proxy-config.yaml";
    local kube_proxy_kubeconfig="${kube_proxy_dir}/kubeconfig";

    mkdir -p "$kube_proxy_dir";

    if [ ! -f "$kp_env" ] || [ ! -f "$kube_proxy_config" ]; then
      warning "kube-proxy configuration files not found."
      return
    fi

    # CLUSTER_IP is globally defined.
    $SED -i "s~CLUSTER_ADDR~https://${CLUSTER_IP}:6443~g" "$kp_env";
    $SED -i "s~PROXY_CONFIG~${kube_proxy_config}~g" "$kp_env";

    $YQ -i ".clusterCIDR=\"${CLUSTER_CIDR}\"" "$kube_proxy_config";
    $YQ -i ".clientConnection.kubeconfig=\"${kube_proxy_kubeconfig}\"" "$kube_proxy_config";
    # Removed cgroupDriver setting as it's typically for Kubelet, not Kube-proxy.
    # Added mode setting (e.g., iptables or ipvs)
    $YQ -i ".mode=\"iptables\"" "$kube_proxy_config";

    info "finished setup_kube_proxy"
}


function main() {
    info "starting main";
    set_peer_ips;
    setup_start_containerd;
    setup_etcd_conf;
    # The following rely on files installed by kube_service_install (in proc.sh)
    # and certs/kubeconfigs generated by kube_configure (in proc.sh).
    setup_kube_apiserver;
    setup_kube_controller_manager;
    setup_kube_scheduler;
    setup_kubelet;
    setup_kube_proxy;
    info "finished main";
}

main;

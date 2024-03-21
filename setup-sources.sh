#!/usr/bin/env sh
#
#MIT License
#
#Copyright (c) 2024 Sean McCully
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
#
# Doc:
#   Configures ETCD, Kubernetes services services and service configurations for multi node cluster.
#


_path=$(dirname "$0")
MESSAGE_HEADER="setup-sources";
source "${_path}/common.sh";

function setup_start_containerd() {
    info "starting setup_start_containerd"

    ctd_config="/etc/containerd/config.toml";

    info "setup_start_containerd  setup containerd config.toml"
    /usr/local/bin/containerd config default > $ctd_config;
    sed -i "s/SystemdCgroup = false/SystemdCgroup = true/" $ctd_config;
    sed -i "s/systemd_cgroup = false/systemd_cgroup = true/" $ctd_config;
    sed -i "s~BinaryName = .*$~BinaryName = \"/usr/local/bin/runc\"~g" $ctd_config;
    sed -i "/plugins\.\"io\.containerd\.grpc\.v1\.cri\"\.registry/{n;s/config_path = .*$/config_path = \"\/etc\/containerd\/certs.d\"/;}" $ctd_config;
    systemctl=$(which systemctl);
    $systemctl daemon-reload;
    $systemctl start containerd;

}

function setup_etcd_conf() {

    info "starting setup_etcd_conf"
    mkdir -p $ETCD_CONF;
    etcd_yml="${ETCD_CONF}/etcd.conf.yml";
    etcd_service_sample="${SRC_DIR}/etcd/contrib/systemd/etcd.service"
    etcd_service_file="${SYSTEMD_SERVICE_PATH}/etcd.service";
    etcd_sysusers="${SRC_DIR}/etcd/contrib/systemd/sysusers.d/20-etcd.conf"
    exec_c "install -m644 ${SRC_DIR}/etcd/etcd.conf.yml.sample ${etcd_yml}";
    exec_c "install -m644 ${etcd_service_sample} ${etcd_service_file}"
    exec_c "sed -i \"s~/usr/bin/etcd~/usr/local/bin/etcd --config-file ${etcd_yml}~g\" ${etcd_service_file}";
    exec_c "install -m644 ${etcd_sysusers} ${SYSUSERS_DIR}/etcd.conf "
    exec_c "${SYSTEMD_SYSUSERS}";

    hostname=$(hostname);
    exec_c "rm -rf ${ETCD_DATA_DIR}"
    exec_c "install -d -o etcd -g etcd ${ETCD_DATA_DIR} "
    exec_c "install -d -m 0700 -o etcd -g etcd ${ETCD_DATA_DIR} "
    cluster_token=$(cat $ETCD_TOKEN_FILE);

    peer_urls="https://${peer_ips[$hostname]}:2380";
    client_urls="https://${peer_ips[$hostname]}:2379";

    cluster="";
    for host in ${!peer_ips[@]}; do
        cluster+="$host=https://${peer_ips[$host]}:2380,";
    done
    cluster=${cluster::-1};
    $YQ -ir ".name=\"${hostname}\"" $etcd_yml;
    $YQ -ir ".data-dir=\"${ETCD_DATA_DIR}\"" $etcd_yml;
    $YQ -ir ".wal-dir=\"${ETCD_DATA_DIR}/wal\"" $etcd_yml;
    $YQ -ir ".listen-peer-urls=\"${peer_urls}\"" $etcd_yml;
    $YQ -ir ".listen-client-urls=\"${client_urls},https://127.0.0.1:2379\"" $etcd_yml;
    $YQ -ir ".initial-advertise-peer-urls=\"${peer_urls}\"" $etcd_yml;
    $YQ -ir ".advertise-client-urls=\"${client_urls}\"" $etcd_yml;
    $YQ -ir ".initial-cluster=\"${cluster}\"" $etcd_yml;
    $YQ -ir ".initial-cluster-token=\"${cluster_token}\"" $etcd_yml;
    $YQ -ir ".initial-cluster-state=\"new\"" $etcd_yml;
    $YQ -ir ".log-level=\"info\"" $etcd_yml;

    $YQ -ir ".client-transport-security.cert-file=\"$ETCD_PKI/server.crt\"" $etcd_yml;
    $YQ -ir ".client-transport-security.key-file=\"$ETCD_PKI/server.key\"" $etcd_yml;
    $YQ -ir ".client-transport-security.trusted-ca-file=\"$ETCD_PKI/ca.crt\"" $etcd_yml;
    $YQ -ir ".client-transport-security.client-cert-auth=true" $etcd_yml;

    $YQ -ir ".peer-transport-security.cert-file=\"$ETCD_PKI/peer.crt\"" $etcd_yml;
    $YQ -ir ".peer-transport-security.key-file=\"$ETCD_PKI/peer.key\"" $etcd_yml;
    $YQ -ir ".peer-transport-security.trusted-ca-file=\"$ETCD_PKI/ca.crt\"" $etcd_yml;
    $YQ -ir ".peer-transport-security.client-cert-auth=true" $etcd_yml;

    info "finished setup_etcd_conf"
}

function configure_apiserver() {

    info "starting configure_apiserver"
    api_server_env="kube-apiserver.env";
    service="kube-apiserver";
}

function setup_kube_apiserver() {

    info "starting setup_kube_apiserver"
    api_env="${KUBE_DIR}/kube-apiserver.env";
    hostname=$(hostname);
    fqdn=$(hostname -f);
    domain=${fqdn#*.};
    bind_ip="${peer_ips[$hostname]}";
    cluster_ip=$($YQ -r '.cluster-ip' $config_yaml);

    service_cert="${KUBE_PKI}/sa.pub";
    service_key="${KUBE_PKI}/sa.key";


    $SED -i "s/CLUSTER_IP/${cluster_ip}/g" $api_env;
    $SED -i "s/IP_ADDR/${bind_ip}/g" $api_env;
    $SED -i "s~SERVICE_CIDR~${SERVICE_CIDR}~g" $api_env;
    $SED -i "s~SERVICE_PKI~${service_cert}~g" $api_env;
    $SED -i "s~SERVICE_KEY~${service_key}~g" $api_env;
    $SED -i "s/DOMAIN_NAME/${domain}/g" $api_env;
    $SED -i "s~PROXY_CA_CERT~${KUBE_PKI}/front-proxy-ca.crt~g" $api_env;
    $SED -i "s~PROXY_CERT~${KUBE_PKI}/front-proxy-client.crt~g" $api_env;
    $SED -i "s~PROXY_KEY~${KUBE_PKI}/front-proxy-client.key~g" $api_env;
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" $api_env;
    $SED -i "s~API_CERT~${KUBE_PKI}/apiserver.crt~g" $api_env;
    $SED -i "s~API_KEY~${KUBE_PKI}/apiserver.key~g" $api_env;
    $SED -i "s~KUBELET_CLIENT_CERT~${KUBE_PKI}/apiserver-kubelet-client.crt~g" $api_env;
    $SED -i "s~KUBELET_CLIENT_KEY~${KUBE_PKI}/apiserver-kubelet-client.key~g" $api_env;
    $SED -i "s~ETCD_CA~${ETCD_PKI}/ca.crt~g" $api_env;
    $SED -i "s~ETCD_CERT~${KUBE_PKI}/apiserver-etcd-client.crt~g" $api_env;
    $SED -i "s~ETCD_KEY~${KUBE_PKI}/apiserver-etcd-client.key~g" $api_env;

    cluster="";
    set_peer_ips;
    for host in ${!peer_ips[@]}; do
        cluster+="https://${peer_ips[$host]}:2379,";
    done
    cluster="${cluster::-1}";
    $SED -i "s~ETCD_SERVERS~${cluster}~g" $api_env;
    info "finished setup_kube_apiserver"

}

function prepare_calico_manifests() {

    tigera_values="${CALICO_SRC}/charts/tigera-operator/values.yaml"
    cluster="";
    set_peer_ips;
    for host in ${!peer_ips[@]}; do
        cluster+="https://${peer_ips[$host]}:2379,";
    done
    $YQ -ir ".peer-transport-security.cert-file=\"$ETCD_PKI/peer.crt\"" $etcd_yml;
    $YQ -ir ".peer-transport-security.key-file=\"$ETCD_PKI/peer.key\"" $etcd_yml;
    $YQ -ir ".peer-transport-security.trusted-ca-file=\"$ETCD_PKI/ca.crt\"" $etcd_yml;

    cluster="${cluster::-1}";
    $YQ -ir ".etcd.endpoints=\"${cluster}\"" $calico_values;
    $YQ -ir ".etcd.tls.crt=\"${ETCD_PKI}/peer.crt\"" $calico_values;
    $YQ -ir ".etcd.tls.ca=\"${ETCD_PKI}/ca.crt\"" $calico_values;
    $YQ -ir ".etcd.tls.key=\"${ETCD_PKI}/peer.key\"" $calico_values;
}

function setup_kube_controller_manager() {

    info "starting setup_kube_controller_manager"

    cm_env="${KUBE_DIR}/kube-controller-manager.env";

    cluster_ip=$($YQ -r '.cluster-ip' $config_yaml);
    service_cert="${KUBE_PKI}/sa.pub";
    service_key="${KUBE_PKI}/sa.key";

    $SED -i "s~CLUSTER_ADDR~https://${cluster_ip}:6443~g" $cm_env;
    $SED -i "s~KUBECONFIG~${KUBE_DIR}/kube-controller-manager.kubeconfig~g" $cm_env;
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" $cm_env;
    $SED -i "s~PROXY_CA~${KUBE_PKI}/front-proxy-ca.crt~g" $cm_env;
    $SED -i "s~SERVICE_KEY~${service_key}~g" $cm_env;
    $SED -i "s~CA_KEY~${KUBE_PKI}/ca.key~g" $cm_env;
    $SED -i "s~CLUSTER_CIDR~${CLUSTER_CIDR}~g" $cm_env;
    $SED -i "s~SERVICE_CIDR~${CLUSTER_CIDR}~g" $cm_env;

    info "finished setup_kube_controller_manager"

}

function setup_kube_scheduler() {

    info "starting setup_kube_scheduler"
    ks_env="${KUBE_DIR}/kube-scheduler.env";
    ks_conf="${KUBE_DIR}/kube-scheduler.kubeconfig";
    ks_yaml="${KUBE_DIR}/kube-scheduler.yaml";

    $SED -i "s~CLUSTER_ADDR~https://${cluster_ip}:6443~g" $ks_env;
    $SED -i "s~CONFIG_YAML~${KUBE_DIR}/kube-scheduler.yaml~g" $ks_env;

    $YQ -ir ".clientConnection.kubeconfig=\"${ks_conf}\"" $ks_yaml;

    info "finished setup_kube_scheduler"

}

function setup_kubelet() {

    info "starting setup_kubelet"
    k_env="${KUBE_DIR}/kubelet.env";
    kubelet_dir=$($YQ -r '.kubelet-dir' $config_yaml);
    cluster_domain=$($YQ -r '.cluster-domain' $config_yaml);
    kubelet_config="${kubelet_dir}/kubelet-config.yaml";
    hostname=$(hostname);
    ip_addr="${peer_ips[$hostname]}";
    svc_cidr="${SERVICE_CIDR%/*}";
    dns_ip="${svc_cidr%.*}.10";

    mkdir -p $kubelet_dir;
    $SED -i "s/IP_ADDR/${ip_addr}/g" $kubelet_config;
    $SED -i "s/KUBELET_DIR/${kubelet_dir}/g" $kubelet_config;
    $SED -i "s/CLUSTER_DOMAIN/${cluster_domain}/g" $kubelet_config;
    $SED -i "s/CLUSTER_DNS/${dns_ip}/g" $kubelet_config;

    containerd_sock=$(ss -nap | grep containerd.sock | grep -v ttrpc | awk '{print $5 }' | head -n 1);

    $SED -i "s~CLUSTER_ADDR~https://${cluster_ip}:6443~g" $k_env;
    $SED -i "s~KUBECONFIG~${kubelet_dir}/kubeconfig~g" $k_env;
    $SED -i "s~CONTAINERD_SOCK~${containerd_sock}~g" $k_env;
    $SED -i "s~KUBELET_CONFIG~${kubelet_config}~g" $k_env;
    $SED -i "s/IP_ADDR/${ip_addr}/g" $kubelet_config;
    $SED -i "s~CA_CERT~${KUBE_PKI}/ca.crt~g" $k_env;
    info "finished setup_kubelet"

}

function setup_kube_proxy() {

    info "starting setup_kube_proxy"
    kp_env="${KUBE_DIR}/kube-proxy.env";
    kube_proxy_dir=$($YQ -r '.kube-proxy-dir' $config_yaml);

    kube_proxy_config="${kube_proxy_dir}/kube-proxy-config.yaml";
    kube_proxy_kubeconfig="${kube_proxy_dir}/kubeconfig";

    mkdir -p $kube_proxy_dir;

    $SED -i "s~CLUSTER_ADDR~https://${cluster_ip}:6443~g" $kp_env;
    $SED -i "s~PROXY_CONFIG~${kube_proxy_config}~g" $kp_env;

    $YQ -ir ".clusterCIDR=\"${CLUSTER_CIDR}\"" $kube_proxy_config;
    $YQ -ir ".clientConnection.kubeconfig=\"${kube_proxy_kubeconfig}\"" $kube_proxy_config;
    $YQ -ir ".cgroupDriver=\"systemd\"" $kube_proxy_config;

    info "finished setup_kube_proxy"

}


function main() {
    info "starting main";
    set_peer_ips;
    setup_start_containerd;
    setup_etcd_conf;
    setup_kube_apiserver;
    setup_kube_controller_manager;
    setup_kube_scheduler;
    setup_kubelet;
    setup_kube_proxy;
    info "finished main";
}

#main;
prepare_calico_manifests;

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
#   Runs additional processes for building and configuring the cluster
#

declare -a pids;
pids_counter=0;
MESSAGE_HEADER="proc";
source ./common.sh;


function validate_certs() {
    info "started validate_certs";

    cert_dir="${PKI_DIR}";
    for _crt in $(find $cert_dir -name "*.crt"); do
        info "validate $_crt";
        _key=$(echo $_crt | sed "s/crt/key/g");
        [ -e  $_key ] || warning "validate_certs ${_key} does not exist";
        certValidate $_crt $_key;
        [ $? == 0 ] || error_message "validate_certs - ${_crt} ${_key} do not match";
    done
}

function generate_etcd_token() {
    info "started generate_etcd_token";
    exec_c "openssl rand -hex -out ${ETCD_TOKEN_FILE} 32";

    if [ -f $config_yaml ]; then
        # Copy certs to additional hosts
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            exec_c "${SCP_COMMAND} ${ETCD_TOKEN_FILE} ${host}:${ETCD_TOKEN_FILE}";
        done
    fi
    info "finished generate_etcd_token";
}

function install_certs() {

    info "started install_certs";
    declare -a installed_certs=();
    doc_path="/opt/cluster/src/website/content/en/docs/setup/best-practices/certificates.md";
    inst_cert="install -o ${KUBE_USER} -g ${KUBE_GROUP} -m 644";
    inst_key="install -o ${KUBE_USER} -g ${KUBE_GROUP} -m 600";
    chown_key="chown ${KUBE_USER}:${KUBE_GROUP}";
    install_dir="install -d -o ${KUBE_USER} -g ${KUBE_GROUP} -m755";
    openssl_decrypt_key="openssl rsa -passin file:$PASS_FILE -in";

    info "install_certs setup systemd-sysusers";
    exec_c "install -m 644 ${CONF_DIR}/kubernetes-sysusers.conf ${SYSUSERS_DIR}/kubernetes-sysusers.conf";
    exec_c $SYSTEMD_SYSUSERS;
    if [ -f $config_yaml ]; then
        # Copy certs to additional hosts
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            exec_c "${SCP_COMMAND} ${CONF_DIR}/kubernetes-sysusers.conf ${host}:${SYSUSERS_DIR}/kubernetes-sysusers.conf";
            exec_c "${SYSTEMD_SYSUSERS}" $host;
        done
    fi

    for _cert_line in $(sed -n '/recommended cert path/,/^ *$/p' $doc_path | tail -n +3 | tr -s ' ' | sed "s/|//g" | tr -s " " | sed "s/,//g" | tr " " ","); do
        certs=(${_cert_line//,/ });
        _installed=false;

        for _ins in ${installed_certs[@]}; do
            if [[ $_ins == ${certs[0]} ]]; then
                info "install_certs ${certs[0]} already installed";
                _installed=true;
            fi
        done

        [ $_installed == true ] && continue;
        installed_certs+=(${certs[0]});
        if [[ $certs[0] =~ .*-ca ]]; then
            ca="${certs[0]::-3}";
            if [ $ca == "front-proxy" ]; then
                ca="kubernetes-front-proxy";
            fi
            dir_name="$(dirname "${PKI_DIR}/${certs[2]}")";
            if [ ! -z $dir_name ]; then
                $install_dir $dir_name;
            fi
            ca_path="${CERT_DIR}/${ca}";
            ca_cert="${PKI_DIR}/${certs[2]}";
            ca_key="${PKI_DIR}/${certs[1]}";
            info "install_certs - ca cert - ${ca_path}/certs/${ca}.cert.pem ${ca_cert}";
            info "install_certs - ca  key - ${ca_path}/private/${ca}.key.pem ${ca_key}";

            exec_c "$inst_cert ${ca_path}/certs/${ca}.cert.pem ${ca_cert}";
            exec_c "$openssl_decrypt_key ${ca_path}/private/${ca}.key.pem -out ${ca_key}";
            exec_c "$chown_key ${ca_key}";
            exec_c "chmod 0600 $ca_key";
        else
            for ca in $($YQ -r ".certs.client | keys | .[]" $CERTS_YAML); do
                cert_file="${CERT_DIR}/${ca}/certs/${certs[0]}.cert.pem";
                key_file="${CERT_DIR}/${ca}/private/${certs[0]}.key.pem";
                info "install_certs -- checking for ${cert_file}";
                if [ -e $cert_file ]; then
                    dir_name="$(dirname "${PKI_DIR}/${certs[2]}")";
                    if [ ! -z $dir_name ]; then
                        $install_dir $dir_name;
                    fi
                    _cert_file="${PKI_DIR}/${certs[2]}";
                    _key_file="${PKI_DIR}/${certs[1]}";

                    info "install_certs -- install cert ${cert_file} ${_cert_file}";
                    info "install_certs -- install key ${key_file} ${_key_file}";
                    exec_c "$inst_cert $cert_file $_cert_file";
                    exec_c "$inst_key $key_file $_key_file";
                fi
            done
        fi
    done
    # install service account
    info "install_certs -- install service-accounts";
    exec_c "$inst_cert ${CERT_DIR}/kubernetes/certs/service-accounts.cert.pem ${PKI_DIR}/sa.pub";
    exec_c "$inst_key ${CERT_DIR}/kubernetes/private/service-accounts.key.pem ${PKI_DIR}/sa.key";

    validate_certs;
    info "finished install_certs";
}

function provision_calico() {
    info "started provision_calico";

    cluster_cidr=$($YQ -r '.cluster-cidr' $config_yaml);
    pool_yaml="/tmp/ippool.yaml"

    calico_manifests;
    exec_c "kubectl apply -f ${CALICO_SRC}/manifests/crds.yaml";
    export KUBECONFIG="/root/.kube/config";
    export DATASTORE_TYPE=kubernetes;

    cat > $pool_yaml <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: pool1
spec:
  cidr: ${cluster_cidr}
  ipipMode: Never
  natOutgoing: true
  disabled: false
  nodeSelector: all()
EOF

   calicoctl create -f $pool_yaml

}


function calico_manifests() {
    info "started calico_manifests";

    export GOPATH="${GOROOT}";
    export PATH="${GOPATH}/bin:${PATH}";
    exec_c "go install golang.org/x/tools/cmd/goimports@latest";

    # TODO: update values.yaml
    exec_c "pushd ${CALICO_SRC}/calicoctl/calicoctl/commands/crds && go generate && popd"
    exec_c "pushd ${CALICO_SRC} && find . -iname \"*.go\" ! -wholename \"./vendor/*\" | xargs goimports -w -local github.com/projectcalico/calico/ && popd"
    exec_c "pushd ${CALICO_SRC} && make gen-manifests && popd"

}

function kubeconfig() {

    kubectl=$(which kubectl);
    kube_config=$1;
    kube_user=$2;
    ca_pem=$3;
    kube_cert=$4;
    kube_key=$5;
    info "started kubeconfig ${kube_config} ${kube_user} ${ca_pem} ${kube_cert} ${kube_key} ${kubectl}";

    exec_c "${kubectl} config set-cluster ${CLUSTER_NAME} \
	--certificate-authority=${ca_pem} --embed-certs=true \
	--server=${CLUSTER_ADDRESS} --kubeconfig=${kube_config}";

    exec_c "${kubectl} config set-credentials ${kube_user} \
	--client-certificate=${kube_cert} --client-key=${kube_key} \
	--embed-certs=true --kubeconfig=${kube_config}";

    exec_c "${kubectl} config set-context default --cluster=${CLUSTER_NAME} \
	--user=${kube_user} --kubeconfig=${kube_config}";

    exec_c "${kubectl} config use-context default --kubeconfig=${kube_config}";
    info "finished kubeconfig";
}

function create_kubeconfigs() {

    info "started create_kubeconfigs";
    controller_crt="${CERT_DIR}/kubernetes/certs/kube-controller-manager.cert.pem";
    controller_key="${CERT_DIR}/kubernetes/private/kube-controller-manager.key.pem";
    controller_config="${KUBE_DIR}/kube-controller-manager.kubeconfig";
    exec_c "kubeconfig $controller_config "system:kube-controller-manager" $PKI_DIR/ca.crt $controller_crt $controller_key";

    scheduler_crt="${CERT_DIR}/kubernetes/certs/kube-scheduler.cert.pem";
    scheduler_key="${CERT_DIR}/kubernetes/private/kube-scheduler.key.pem";
    scheduler_config="${KUBE_DIR}/kube-scheduler.kubeconfig";
    exec_c "kubeconfig $scheduler_config "system:kube-scheduler" $PKI_DIR/ca.crt $scheduler_crt $scheduler_key";

    super_admin_crt="${CERT_DIR}/kubernetes/certs/kubernetes-super-admin.cert.pem";
    super_admin_key="${CERT_DIR}/kubernetes/private/kubernetes-super-admin.key.pem";
    super_admin_config="${KUBE_DIR}/super-admin.kubeconfig";
    exec_c "kubeconfig $super_admin_config "kubernetes-super-admin" $PKI_DIR/ca.crt $super_admin_crt $super_admin_key";
    exec_c "chmod 0400 $scheduler_config";

    admin_crt="${CERT_DIR}/kubernetes/certs/admin.cert.pem";
    admin_key="${CERT_DIR}/kubernetes/private/admin.key.pem";
    admin_config="/root/.kube/config";
    exec_c "kubeconfig $admin_config "admin" $PKI_DIR/ca.crt $admin_crt $admin_key"

    cni_crt="${CERT_DIR}/kubernetes/certs/calico-cni.cert.pem";
    cni_key="${CERT_DIR}/kubernetes/private/calico-cni.key.pem";
    cni_config="${CNI_CONF_DIR}/calico-kubeconfig";
    exec_c "kubeconfig $cni_config "calico-cni" $PKI_DIR/ca.crt $cni_crt $cni_key";
    exec_c "chmod 600 ${cni_config}";


    kube_proxy_dir=$($YQ -r '.kube-proxy-dir' $config_yaml);
    kube_proxy_crt="${CERT_DIR}/kubernetes/certs/kube-proxy.cert.pem";
    kube_proxy_key="${CERT_DIR}/kubernetes/private/kube-proxy.key.pem";
    kube_proxy_config="${kube_proxy_dir}/kubeconfig";
    exec_c "kubeconfig $kube_proxy_config system:kube-proxy $PKI_DIR/ca.crt $kube_proxy_crt $kube_proxy_key"
    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        exec_c "mkdir -p ${kube_proxy_dir}" $host;
        exec_c "$SCP_COMMAND $kube_proxy_config  $host:${kube_proxy_config}";
        exec_c "$SCP_COMMAND $cni_config  $host:${cni_config}";
    done
    info "finished create_kubeconfigs";
}

function kube_proxy() {

    kube_proxy_dir=$($YQ -r '.kube-proxy-dir' $config_yaml);
    kube_proxy_crt="${CERT_DIR}/kubernetes/certs/kube-proxy.cert.pem";
    kube_proxy_key="${CERT_DIR}/kubernetes/private/kube-proxy.key.pem";
    kube_proxy_config="${kube_proxy_dir}/kubeconfig";
    exec_c "kubeconfig $kube_proxy_config system:node-proxier $PKI_DIR/ca.crt $kube_proxy_crt $kube_proxy_key"
    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        exec_c "mkdir -p ${kube_proxy_dir}" $host;
        exec_c "$SCP_COMMAND $kube_proxy_config  $host:${kube_proxy_config}";
        exec_c "$SCP_COMMAND $cni_config  $host:${cni_config}";
    done
}

function create_kubelet_kubeconfig() {

    info "started create_kubelet_kubeconfig";
    kubelet_dir=$($YQ -r '.kubelet-dir' $config_yaml);

    # Create kubelet kubeconfig
    hostname=$(hostname);
    kubelet_crt="${CERT_DIR}/kubernetes/certs/${hostname}.cert.pem";
    kubelet_key="${CERT_DIR}/kubernetes/private/${hostname}.key.pem";
    kubelet_config="${kubelet_dir}/kubeconfig";
    exec_c "cp ${kubelet_crt} ${kubelet_dir}/kubelet.crt"
    exec_c "cp ${kubelet_key} ${kubelet_dir}/kubelet.key"
    kubeconfig $kubelet_config "system:node:${hostname}" $PKI_DIR/ca.crt $kubelet_crt $kubelet_key

        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            # Create kubelet kubeconfig for additional hosts
            kubelet_crt="${CERT_DIR}/kubernetes/certs/${host}.cert.pem";
            kubelet_key="${CERT_DIR}/kubernetes/private/${host}.key.pem";
            kubelet_config="/tmp/kubelet-config";
            kubeconfig $kubelet_config "system:node:${host}" $PKI_DIR/ca.crt $kubelet_crt $kubelet_key
            exec_c "mkdir -p ${kubelet_dir}" $host;
            exec_c "${SCP_COMMAND} ${kubelet_config}  ${host}:${kubelet_dir}/kubeconfig";
            exec_c "${SCP_COMMAND} ${kubelet_crt}  ${host}:${kubelet_dir}/kubelet.crt";
            exec_c "${SCP_COMMAND} ${kubelet_key}  ${host}:${kubelet_dir}/kubelet.key";
            exec_c "rm ${kubelet_config}";
        done
    info "finished create_kubelet_kubeconfig";
}

function kube_service_install() {

    info "started kube_service_install";

    kubelet_dir=$($YQ -r '.kubelet-dir' $config_yaml);
    kubelet_config="${kubelet_dir}/kubelet-config.yaml";

    kube_proxy_dir=$($YQ -r '.kube-proxy-dir' $config_yaml);
    kube_proxy_config="${kube_proxy_dir}/kube-proxy-config.yaml";

    exec_c "install -m 644 ${SERVICE_DIR}/*.env ${KUBE_DIR}/";
    exec_c "install -m 644 ${SERVICE_DIR}/*.service ${SYSTEMD_SERVICE_PATH}"
    exec_c "install -m 544 ${CONF_DIR}/50-sysctl.conf /etc/sysctl.d/50-sysctl.conf"
    exec_c "install -D -m 644 ${CONF_DIR}/kube-proxy-config.yaml ${kube_proxy_config}";
    exec_c "install -D -m 644 ${CONF_DIR}/kubelet-config.yaml ${kubelet_config}";
    exec_c "install -D -m 644 ${CONF_DIR}/kube-scheduler.yaml ${KUBE_DIR}/kube-scheduler.yaml";

    exec_c "modprobe tcp_bbr && depmod -a";
    exec_c "modprobe sch_cake && depmod -a";
    exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${KUBE_DIR}";
    exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${kube_proxy_dir}";
    exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${kubelet_dir}";
    sysctl=$(command -v sysctl);
    exec_c "${sysctl} --system > /dev/null";

    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        exec_c "install -d $KUBE_DIR" $host;
        exec_c "$SCP_COMMAND $SERVICE_DIR/*.env  $host:${KUBE_DIR}/";
        exec_c "$SCP_COMMAND $SERVICE_DIR/*.service  $host:$SYSTEMD_SERVICE_PATH/";

        exec_c "install -d $kubelet_dir" $host;
        exec_c "install -d $kube_proxy_dir" $host;
        exec_c "$SCP_COMMAND $CONF_DIR/kube-proxy-config.yaml $host:$kube_proxy_config";
        exec_c "$SCP_COMMAND $CONF_DIR/kubelet-config.yaml $host:$kubelet_config";

        exec_c "modprobe tcp_bbr && depmod -a" $host;
        exec_c "modprobe sch_cake && depmod -a" $host;
        echo "$SCP_COMMAND $CONF_DIR/50-sysctl.conf $host:/etc/sysctl.d/";
        exec_c "${sysctl} --system > /dev/null" $host;

        exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${KUBE_DIR}" $host;
        exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${kube_proxy_dir}" $host;
        exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${kubelet_dir}" $host;
    done
    info "finished kube_service_install";
}

function exec_remote() {
    _script=$1;
    info "started exec_remote ${_script}";
    if [ -f $config_yaml ]; then
        # If a config.yaml exists and additoinal hosts defined, execcute script on those hosts.
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            exec_c "${SCP_COMMAND} ${_script} ${host}:/tmp/${_script}"
            exec_c "${SCP_COMMAND} ./common.sh ${host}:/tmp/common.sh"
            [ $CLEAN == true ] && exec_c "sed -i \"s/CLEAN=false/CLEAN=true/g\" /tmp/common.sh" ${host};
            exec_c "${SCP_COMMAND} ${config_yaml} ${host}:/tmp/config.yaml"
            exec_c "${SCP_COMMAND} ${hosts_yaml} ${host}:/tmp/hosts.yaml"
            exec_c "chmod 744 /tmp/${_script}" ${host};
            $SSH_COMMAND $host "/tmp/${_script} 2> /tmp/${_script}.err 1> /tmp/${_script}.out" &
            pids[${pids_counter}]=$!;
            pids_counter=$[$pids_counter + 1];
            info "started ${_script} on ${host}";
        done
    fi
    info "finished exec_remote ${_script}";
}

function remote_cleanup() {
    _script=$1;
    info "started remote_cleanup ${_script}";
    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        info "remove tmp files from ${host}";
        exec_c "rm /tmp/common.sh" $host;
        exec_c "rm /tmp/config.yaml" $host;
        exec_c "rm /tmp/hosts.yaml" $host;
        exec_c "rm /tmp/${_script}" $host;
        exec_c "$SCP_COMMAND $host:/tmp/$_script.err ./logs/${host}.$_script.err";
        exec_c "$SCP_COMMAND $host:/tmp/$_script.out ./logs/${host}.$_script.out";
        exec_c "rm /tmp/${_script}.{err,out}" $host;
    done
}

function exec_script() {
    _script=$1;
    _remote=${2:-false};
    info "started exec_script ${_script} ${_remote}";
    [ ! -d "./logs" ] && exec_c "mkdir -p logs";
    [ -z $_script ] && error_message "Script name required";
    [ ! -f "./$_script" ] && error_message "Script ${_script} does not exist";
    cd $script_dir;
    pids_counter=0;
    info "starting local ${_script}";
    ./${_script} 2> logs/${_script}.err 1> logs/${_script}.out &
    pids[${pids_counter}]=$!

    pids_counter=$[$pids_counter + 1];
    [[ $_remote == true ]] && exec_remote $_script;
    # Wait for source builder processes to finish;
    for pid in ${pids[*]}; do
        wait $pid;
    done
    info "${_script} finished";
    [[ $_remote == true  ]] && remote_cleanup $_script;
    info "finished exec_script ${_script} ${_remote}";
}


function vrrp_configure() {

    [ -z ${peer_ips} ] && set_peer_ips;
    host=${1:-"local"};
    prio=${2:-"30"};
    k_conf=${3};
    info "started vrrp_configure $host $prio";

    if [[ $host == "local" ]]; then
        hostname=$local_hostname;
    else
        hostname=$host;
    fi
    info "started vrrp_configure hostname ${hostname}";

    local_hostname=$(hostname)
    host_ip="${peer_ips[${hostname}]}";
    local_ip="${peer_ips[${local_hostname}]}";
    info "started vrrp_configure host_ip ${host_ip}";
    intf=$(ip -br -4 a sh | grep $local_ip | awk '{print $1}');
    intf="${intf%%@*}";
    router_id="$((1 + $RANDOM % 10))";
    auth_pass=$(openssl rand -hex 24);
    prio=25;
    exec_c "sed -i \"s/INTERFACE/${intf}/g\" $k_conf";
    exec_c "sed -i \"s/ROUTER_ID/${router_id}/g\" $k_conf";
    exec_c "sed -i \"s/PRIO/${prio}/g\" $k_conf";
    exec_c "sed -i \"s/AUTH_PASS/${auth_pass}/g\" $k_conf";
    exec_c "sed -i \"s~IP_ADDR~$CLUSTER_IP/24~g\" $k_conf";

    virtual_server_doc="""
        virtual_server IP_ADDR PORT {
        delay_loop 6
        lvs_method NAT
        protocol TCP

""";
    real_server_doc="""
    real_server IP_ADDR 6443 {
        TCP_CHECK {
            connect_port 6443
        }
    }
""";

    for _p in "6443" "443"; do
        virtual_server=$virtual_server_doc;
        virtual_server=${virtual_server/PORT/${_p}};
        virtual_server=${virtual_server/IP_ADDR/${CLUSTER_IP}};
        rs_doc=$real_server_doc;
        rs_doc=${rs_doc/IP_ADDR/$host_ip};
        virtual_server+="\n${rs_doc}\n";
        virtual_server+="\n}";
        printf "${virtual_server}" >> $k_conf;
    done

    info "finished vrrp_configure";
}

function keepalived_configure() {

    info "started keepalived_configure";
    k_conf="/usr/local/etc/keepalived/keepalived.conf";
    k_conf_dir=$(dirname $k_conf);
    k_conf_s="$CONF_DIR/keepalived.conf";
    prio="30";

    if [ -f $config_yaml ]; then
        # Copy certs to additional hosts
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            exec_c "install -m 644 $k_conf_s  $k_conf";
            vrrp_configure $host $prio $k_conf;
            exec_c "$SCP_COMMAND  $k_conf $host:$k_conf";
            exec_c "sed -i \"s/MASTER/BACKUP/g\" ${k_conf}" $host;
            prio=$[$prio - "1"];
            exec_c "sed -i \"s/priority .*/priority ${prio}/g\" ${k_conf}" $host;
        done;
    fi
    k_conf="/usr/local/etc/keepalived/keepalived.conf";
    k_conf_dir=$(dirname $k_conf);
    k_conf_s="$CONF_DIR/keepalived.conf";
    exec_c "install -m 644 $k_conf_s  $k_conf";
    vrrp_configure "local" $prio $k_conf;
}

function kube_configure() {
    info "started kube_configure";

    install_certs;
    create_kubeconfigs;
    create_kubelet_kubeconfig;
    kube_service_install;
    exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${KUBE_PKI}";
    exec_c "chown -R ${ETCD_USER}:${ETCD_GROUP} ${ETCD_PKI}";

    for ca_cert in "${KUBE_PKI}/ca.crt" "${KUBE_PKI}/front-proxy-ca.crt" "${ETCD_PKI}/ca.crt"; do
        exec_c "trust anchor ${ca_cert}";
    done
    if [ -f $config_yaml ]; then
        # Copy certs to additional hosts
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            info "make ${KUBE_DIR} on ${host}";
            exec_c "mkdir -p ${KUBE_DIR}" $host;
            info "copy kube conf to ${host}";
            exec_c "$SCP_COMMAND -r $KUBE_DIR/* $host:$KUBE_DIR 1> /dev/null";
            exec_c "chown -R ${KUBE_USER}:${KUBE_GROUP} ${KUBE_DIR}" $host;
            exec_c "chown -R ${ETCD_USER}:${ETCD_GROUP} ${ETCD_PKI}" $host;
            for ca_cert in "${KUBE_PKI}/ca.crt" "${KUBE_PKI}/front-proxy-ca.crt" "${ETCD_PKI}/ca.crt"; do
                exec_c "trust anchor ${ca_cert}" $host;
            done
        done
    fi

    info "finished kube_configure";
}

function manage_services() {
    _s=${1:-stop};
    info "started manage_services ${_s}";

    sys_reload="${SYSTEMCTL} daemon-reload";
    exec_c "${sys_reload}";
    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        exec_c "${sys_reload}" $host;
    done

    services=("containerd" "keepalived" "etcd" "kube-apiserver" "kube-scheduler" "kube-controller-manager" "kubelet" "kube-proxy");
    for service in ${services[@]}; do
        debug "manage_services ${_s} ${service}";
        exec_c "${SYSTEMCTL} "$_s" ${service}&";
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            exec_c "${SYSTEMCTL} ${_s} ${service}" $host;
        done
    done
    info "finished manage_services ${_s}";
}

function stop_services() {
    info "stop_services";
    manage_services "stop";
}

function start_services() {
    info "start_services";
    manage_services "start";
}

function cleanup() {

    info "started cleanup";
    [ $SERVICES == true ] && stop_services;
    kubelet_dir=$($YQ -r '.kubelet-dir' $config_yaml);
    kube_proxy_dir=$($YQ -r '.kube-proxy-dir' $config_yaml);
    exec_c "rm -rf logs/*.{err,out}";
    exec_c "rm -rf $KUBE_DIR";
    exec_c "rm -rf $ETCD_DATA_DIR";
    exec_c "rm -rf $KUBE_DIR";
    exec_c "rm -rf $kubelet_dir";
    exec_c "rm -rf $kube_proxy_dir";
    for host in $(yq -r ".hosts | .[]" $config_yaml); do
        exec_c "rm -rf $KUBE_DIR" $host;
        exec_c "rm -rf $kubelet_dir" $host;
        exec_c "rm -rf $kube_proxy_dir" $host;
    done
}

function trap_sigint() {
    info "started trap_sigint";
    for pid in ${pids[*]}; do
        kill -9 $pid;
    done
    error_message "SIGINT";
}

function argparse() {
    info "finished argparse";
}

function main() {
    info "started main";
    [ $CLEAN == false ] && info "Skipping cleanup";
    [ $CLEAN == true ] && cleanup;
    [ $SERVICES == true ] && stop_services;
    [ $SERVICES == false ] && info "Skipping stop services";
    set_peer_ips;
    [ $BUILD_SOURCE == true ] && exec_script "source-builder.sh" true;
    [ $BUILD_SOURCE == false ] && info "Skipping source-builder.sh";
    generate_etcd_token;
    info "Creating Certificate Authority";
    # Create CA and certs for kubernetes cluster
    [ $RUN_CERTS == true ] && exec_script "cert-manager.sh" false;
    [ $RUN_CERTS == false ] && info "Skipping cert-manager.sh";
    keepalived_configure;
    kube_configure;
    exec_script "setup-sources.sh" true;
    [ $SERVICES == true ] && start_services;
    [ $SERVICES == false ] && info "Skipping start services";
    provision_calico;
    info "finished main";
}


ARGS=$(getopt -o scxylh --long src,certs,setup,services,clean,help -- "$@")
if [[ $? -ne 0 ]]; then
    printf "${usage}";
    exit 1;
fi

eval set -- "$ARGS"
while [ : ]; do
    case "$1" in
    -s | --src)
        BUILD_SOURCE=false;
        shift;
        ;;
    -c | --certs)
        RUN_CERTS=false;
        shift;
        ;;
    -x | --setup)
        RUN_SETUP=false;
        shift;
        ;;
    -y | --services)
        SERVICES=false;
        shift;
        ;;
    -l | --clean)
        CLEAN=true;
        shift;
        ;;
    -h | --help)
        printf "${usage}";
        exit 0;
        ;;
    --) shift;
        break
        ;;
  esac
done

main;

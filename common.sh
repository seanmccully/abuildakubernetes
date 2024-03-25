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
#   Global variables and functions
#

declare -r LOG_LEVEL_DEBUG=0
declare -r LOG_LEVEL_INFO=1
declare -r LOG_LEVEL_MESSAGE=2
declare -r LOG_LEVEL_WARNING=3
declare -r LOG_LEVEL_ERROR=4
declare -r LOG_NO_MESSAGE="--";
declare -r DEFAULT_TIME_FORMAT="%Y-%m-%d %H:%M.%S"
TIME_FORMAT=${TIME_FORMAT:-$DEFAULT_TIME_FORMAT}

declare -A peer_ips;

DEBUG=${DEBUG:-0};
VERBOSE=${VERBOSE:-1};
BUILD_SOURCE=true;
RUN_CERTS=true;
RUN_SETUP=true;
SERVICES=true;
CLEAN=false;
usage="""$(basename "$0") [-h] [-s -c -x -y -l] -- Options are inverted to not run source-builder [-s]

where:
    -s, --src -- Exclude source-builder.sh
    -c, --certs -- Exclude cert-manager (idempotent) script.
    -x, --setup -- Exclude setup-sources.sh
    -y, --services -- Do not stop or start services
    -l, --clean -- Clean previous builds

"""
MESSAGE_HEADER=${MESSAGE_HEADER:-common};
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
config_yaml="${script_dir}/config.yaml";
hosts_yaml="${script_dir}/hosts.yaml";

SSL_CNF="${script_dir}/conf/openssl.cnf"
INTER_SSL_CNF="${script_dir}/conf/intermediate-openssl.cnf"

YQ=$(command -v yq);
SED=$(command -v sed);
ssh=$(command -v ssh);
scp=$(command -v scp);
git=$(command -v git);
python=$(command -v python);
openssl=$(command -v openssl);

SSH_COMMAND="${ssh} -o StrictHostKeyChecking=accept-new";
SCP_COMMAND="${scp} -o StrictHostKeyChecking=accept-new";

BUILD_DIR=$($YQ -r '.build-dir' $config_yaml);
PKI_DIR=$($YQ -r '.kube-pki' $config_yaml);
KUBE_DIR=$($YQ -r '.kube-dir' $config_yaml);
CLUSTER_NAME=$($YQ -r '.cluster-name' $config_yaml);
KUBE_PKI=$($YQ -r '.kube-pki' $config_yaml);
KUBE_DIR=$($YQ -r '.kube-dir' $config_yaml);
CLUSTER_IP=$($YQ -r '.cluster-ip' $config_yaml)
CLUSTER_ADDRESS="https://${CLUSTER_IP}:6443";
SERVICE_CIDR=$($YQ -r '.service-cidr' $config_yaml);
CLUSTER_CIDR=$($YQ -r '.cluster-cidr' $config_yaml);

CERT_DIR="${BUILD_DIR}/certs";
SRC_DIR="${BUILD_DIR}/src";
GOROOT="${SRC_DIR}/go";
CALICO_SRC="$SRC_DIR/calico";
CNI_CONF_DIR="/etc/cni/net.d";
CNI_BIN_DIR="/opt/cni/bin";

CA_PASS=$(openssl rand -hex 12);
PASS_FILE="$CERT_DIR/.ca_pass";

SYSTEMCTL=$(command -v systemctl)
SYSTEMD_SYSUSERS=$(command -v systemd-sysusers);
SYSTEMD_SERVICE_PATH=$(dirname $($SYSTEMCTL show -P FragmentPath $($SYSTEMCTL status | grep ".service" | head -n 1 | tr '├─' ' ' | awk '{ print $2 }')));
SYSUSERS_DIR=$(dirname $(systemd-sysusers --cat-config | head -n 1 | awk '{ print $2 }'));

ETCD_PKI="${KUBE_PKI}/etcd";
ETCD_DATA_DIR="/var/lib/etcd";
ETCD_TOKEN_FILE="/tmp/cluster.token";
CERTS_YAML="${script_dir}/certs.yaml";
SERVICE_DIR="${script_dir}/services"
CONF_DIR="${script_dir}/conf"
KUBE_USER="kube";
KUBE_GROUP="kube";
ETCD_CONF="/etc/etcd";
ETCD_USER="etcd";
ETCD_GROUP="etcd";


# REPOS ##
GO="https://go.googlesource.com/go"
GOLANGCI="https://github.com/golangci/golangci-lint.git"
GOMD2MAN="https://github.com/cpuguy83/go-md2man.git";
ETCD="https://github.com/etcd-io/etcd.git"
KUBE="https://github.com/kubernetes/kubernetes.git"
CALICO="https://github.com/projectcalico/calico.git"
CNI_PLUGINS="https://github.com/containernetworking/plugins.git"
CONTAINERD="https://github.com/containerd/containerd.git"
RUNC="https://github.com/opencontainers/runc.git";
KUBE_DOCS="https://github.com/kubernetes/website.git"
KEEPALIVED="https://github.com/acassen/keepalived.git"
HELM="https://github.com/helm/helm";
CRITOOLS="https://github.com/kubernetes-sigs/cri-tools.git"

function isRootUser() {
  [[ "$( whoami )" == "root" ]]
}

function exec_c() {
    command=$1;
    ret_code=${2:-0};
    debug "start exec_c ${command}"
    _host=${2:-"local"};
    if [[ $_host == "local" ]]; then
        eval "${command}" || error_message "${command} failed with err: $?" $ret_code
    else
        output=$($SSH_COMMAND $_host $command);
        ret=$($SSH_COMMAND $_host "echo $?");
        [[ $ret == "0" ]] || error_message "${command} on ${_host} failed with err: $ret - $output" $ret_code;
    fi
    debug "finished exec_c ${command}";
}

function write_message() {
  local _level="$1" _message="$2" _newLine="${3:-1}" _exitCode="${4:--1}"

  # Safe-guard on numeric values (if this function is directly called).
  [ "$( echo "$_newLine" |grep -ce "^[0-9]$" )" -ne 1 ] && _newLine="1"
  [ "$( echo "$_exitCode" |grep -ce "^-*[0-9][0-9]*$" )" -ne 1 ] && _exitCode="-1"

  # Does nothing if INFO message and NOT BSC_VERBOSE.
  [ "$DEBUG" -eq 0 ] && [ "$_level" = "$LOG_LEVEL_DEBUG" ] && return 0
  [ "$VERBOSE" -eq 0 ] && [ "$DEBUG" -eq 0 ] && [ "$_level" = "$LOG_LEVEL_INFO" ] && return 0

  # Manages level.
  _messagePrefix=""
  [ "$_level" = "$LOG_LEVEL_DEBUG" ] && _messagePrefix="DEBUG: "
  [ "$_level" = "$LOG_LEVEL_INFO" ] && _messagePrefix="INFO: "
  [ "$_level" = "$LOG_LEVEL_WARNING" ] && _messagePrefix="\E[31m\E[4mWARNING\E[0m: "
  [ "$_level" = "$LOG_LEVEL_ERROR" ] && _messagePrefix="\E[31m\E[4mERROR\E[0m: "

  # Checks if message must be shown on console.
  _timestamp=$( get_datetime "$TIME_FORMAT" )
  printf "%-17s %-15s $_messagePrefix%b\n" "$_timestamp" "[${MESSAGE_HEADER}]" "$_message"

  # Manages exit if needed.
  [ "$_exitCode" -eq -1 ] && return 0
  exit "$_exitCode"

}

function get_datetime() {
  local _dateFormat="$1"

  date +"$_dateFormat"
}

function debug() {
  write_message $LOG_LEVEL_DEBUG "${1:-$LOG_NO_MESSAGE}" "${2:-1}"
}

function info() {
  write_message $LOG_LEVEL_INFO "${1:-$LOG_NO_MESSAGE}" "${2:-1}"
}

function warning() {
  write_message $LOG_LEVEL_WARNING "${1:-$LOG_NO_MESSAGE}" "${2:-1}" >&2
}

function error_message() {
  write_message $LOG_LEVEL_ERROR "${1:-""}" 1 "${2:-101}" >&2
}

function checkBin() {
    _binary="$1";
    [ -x "$_binary" ] && return 0;

    error_message "Binary '$_binary' found but it does not have *exec_cute* permission." 102
}

function certValidate() {

    cert_file=$1;
    key_file=$2;
    if openssl x509 -checkend 86400 -noout -in $cert_file; then
        if [[ $(openssl x509 -noout -modulus -in $cert_file) == $(openssl rsa -noout -modulus -in $key_file) ]]; then
            return 0;
        fi
    fi
    return 1;
}

function get_host_ips() {

    info "starting get_host_ips";
    declare -A ips_host;
    ip_proc="/sbin/ip -o -4 addr list | awk '{print \$4}' | cut -d\/ -f1";

    hostname=$(hostname);
    ips=();
    for _ip in $(eval $ip_proc); do
        ips+=($_ip);
    done
    ips_host["${hostname}"]="${ips[@]}";

    if [ -f $config_yaml ]; then
        for host in $(yq -r ".hosts | .[]" $config_yaml); do
            hostname=$(eval $SSH_COMMAND $host hostname);
            ips=();
            for _ip in $(eval $SSH_COMMAND $host "${ip_proc}"); do
                ips+=($_ip);
            done
            ips_host["${hostname}"]="${ips[@]}";
        done
    fi
    echo "---" > $hosts_yaml;
    for host in ${!ips_host[@]}; do
        echo "${host}:" >> $hosts_yaml;
        for ips in ${ips_host[$host]}; do
            echo "  - ${ips}" >> $hosts_yaml;
        done
    done

    info "finished get_host_ips";
}

function set_peer_ips() {
    info "starting set_peer_ips"
    python=$(command -v python3);
    [ ! -e $hosts_yaml ] && get_host_ips;

    if [ ! -z $python ]; then
        py_ip="import ipaddress;import sys;sys.exit(0) if ipaddress.ip_address(sys.argv[2]) in ipaddress.ip_network(sys.argv[1]) else sys.exit(1)"
        cidr=$($YQ -r ".control-plane-subnet" $config_yaml)
        master_ip=$($YQ -r ".cluster-ip" $config_yaml)
        for host in $($YQ -r 'keys | .[]' $hosts_yaml); do
            for ip in $($YQ -r ".${host} | .[]" $hosts_yaml); do
                if $($python -c "${py_ip}" $cidr $ip); then
                    if [ $ip != $master_ip ]; then
                        peer_ips["${host}"]=$ip;
                    fi
                fi
            done
        done
    else
        nmap=$(which nmap);
    fi

    info "finished set_peer_ips"
}

checkBin $YQ
checkBin $SED
checkBin $ssh
checkBin $scp


isRootUser || error_message "Script requires root"

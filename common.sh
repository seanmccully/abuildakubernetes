#!/usr/bin/env bash
#
#MIT License
# ... (License text omitted for brevity) ...
#
# Doc:
#   Global variables and functions
#

# Set strict mode
set -euo pipefail

declare -r LOG_LEVEL_DEBUG=0
declare -r LOG_LEVEL_INFO=1
declare -r LOG_LEVEL_WARNING=3
declare -r LOG_LEVEL_ERROR=4
declare -r LOG_NO_MESSAGE="--";
declare -r DEFAULT_TIME_FORMAT="%Y-%m-%d %H:%M.%S"
TIME_FORMAT=${TIME_FORMAT:-$DEFAULT_TIME_FORMAT}

# Associative array requires Bash
declare -A peer_ips;

# Initialize variables with defaults if not set
DEBUG=${DEBUG:-0};
VERBOSE=${VERBOSE:-1};
BUILD_SOURCE=${BUILD_SOURCE:-false};
RUN_CERTS=${RUN_CERTS:-false};
RUN_SETUP=${RUN_SETUP:-true};
SERVICES=${SERVICES:-true};
CLEAN=${CLEAN:-false};

usage="$(basename "$0") [-h] [-s -c -x -y -l]

Options (Flags disable the corresponding action):
    -s, --src       Exclude source-builder.sh
    -c, --certs     Exclude cert-manager.sh
    -x, --setup     Exclude setup-sources.sh
    -y, --services  Do not stop or start services
    -l, --clean     Clean previous builds
    -h, --help      Show this help message
"
MESSAGE_HEADER=${MESSAGE_HEADER:-common};

# Reliable script directory detection
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
config_yaml="${script_dir}/config.yaml";
hosts_yaml="${script_dir}/hosts.yaml";

SSL_CNF="${script_dir}/conf/openssl.cnf"
INTER_SSL_CNF="${script_dir}/conf/intermediate-openssl.cnf"

# Define commands, preferring python3
YQ=$(command -v yq || true);
SED=$(command -v sed || true);
ssh=$(command -v ssh || true);
scp=$(command -v scp || true);
git=$(command -v git || true);
python=$(command -v python3 || command -v python || true);
openssl=$(command -v openssl || true);

# Check for essential binaries early
if [ -z "$YQ" ] || [ -z "$SED" ] || [ -z "$ssh" ] || [ -z "$scp" ] || [ -z "$python" ] || [ -z "$openssl" ]; then
  echo "ERROR: Required binaries (yq, sed, ssh, scp, python, openssl) not found." >&2
  exit 1
fi

SSH_COMMAND="${ssh} -o StrictHostKeyChecking=accept-new";
SCP_COMMAND="${scp} -o StrictHostKeyChecking=accept-new";

# Check if config_yaml exists
if [ ! -f "$config_yaml" ]; then
  echo "ERROR: Configuration file not found: ${config_yaml}" >&2
  exit 1
fi

# Read configuration
BUILD_DIR=$($YQ -r '.buildDir' $config_yaml);
KUBE_PKI=$($YQ -r '.kubePki' $config_yaml);
PKI_DIR=$KUBE_PKI # Alias
KUBE_DIR=$($YQ -r '.kubeDir' $config_yaml);
CLUSTER_NAME=$($YQ -r '.clusterName' $config_yaml);
CLUSTER_IP=$($YQ -r '.clusterIp' $config_yaml)
CLUSTER_ADDRESS="https://${CLUSTER_IP}:6443";
SERVICE_CIDR=$($YQ -r '.serviceCidr' $config_yaml);
CLUSTER_CIDR=$($YQ -r '.clusterCidr' $config_yaml);
CLUSTER_DOMAIN=$($YQ -r '.clusterDomain' $config_yaml);
KUBELET_DIR=$($YQ -r '.kubeletDir' "$config_yaml");

CERT_DIR="${BUILD_DIR}/certs";
SRC_DIR="${BUILD_DIR}/src";

# Ensure BUILD_DIR exists
mkdir -p "$BUILD_DIR"

# Set GOROOT if not already set
if [ -z "${GOROOT:-}" ]; then
  GOROOT="${SRC_DIR}/go";
fi

CALICO_SRC="$SRC_DIR/calico";
CNI_CONF_DIR="/etc/cni/net.d";
CNI_BIN_DIR="/opt/cni/bin";

# CA Password handling: Generate and store if file doesn't exist
PASS_FILE="$CERT_DIR/.ca_pass";
if [ ! -f "${PASS_FILE}" ]; then
  mkdir -p "$CERT_DIR"
  CA_PASS=$(openssl rand -hex 12);
  echo "$CA_PASS" > "$PASS_FILE"
  chmod 0400 "$PASS_FILE"
else
  CA_PASS=$(cat "$PASS_FILE");
fi

SYSTEMCTL=$(command -v systemctl || true)
SYSTEMD_SYSUSERS=$(command -v systemd-sysusers || true);

# Improved SystemD path detection
SYSTEMD_SERVICE_PATH="/etc/systemd/system" # Default fallback
if command -v pkg-config &> /dev/null && pkg-config systemd &> /dev/null; then
    SYSTEMD_SERVICE_PATH=$(pkg-config --variable=systemdsystemunitdir systemd)
elif [ -n "$SYSTEMCTL" ]; then
  # Try detecting path from a common service if pkg-config fails
  PATH_DETECTED=$($SYSTEMCTL show --property=FragmentPath --value systemd-logind.service 2>/dev/null | xargs dirname || true)
  if [ -n "$PATH_DETECTED" ] && [ -d "$PATH_DETECTED" ]; then
    SYSTEMD_SERVICE_PATH=$PATH_DETECTED
  fi
fi

SYSUSERS_DIR="/etc/sysusers.d" # Default fallback
if [ -n "$SYSTEMD_SYSUSERS" ]; then
    _sysusers_config=$(systemd-sysusers --cat-config 2>/dev/null | grep -v '^#' | head -n 1 | awk '{ print $2 }' || true)
    if [ -n "$_sysusers_config" ]; then
        SYSUSERS_DIR=$(dirname "$_sysusers_config")
    fi
fi


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
  # Use id -u for reliable root check
  [[ "$( id -u )" -eq 0 ]]
}

# Robust command execution function. Executes command and returns exit status.
# Usage: exec_c <command_string> [host]
function exec_c() {
    local command="$1"
    local _host="${2:-local}"

    debug "start exec_c ${command} on ${_host}"

    # Use bash -c to execute the command string safely in a subshell.
    if [[ "$_host" == "local" ]]; then
        # We must disable 'set -e' temporarily to capture the exit status ourselves.
        set +e
        output=$(bash -c "${command}" 2>&1)
        local exit_status=$?
        set -e
    else
        # Execute command remotely
        set +e
        # Quoting for remote execution: Single quotes around the command assume the command string itself is safely constructed.
        output=$($SSH_COMMAND "$_host" "bash -c '${command}'" 2>&1)
        local exit_status=$?
        set -e
    fi

    # Handle failure
    if [ $exit_status -ne 0 ]; then
          # Print output if any
          [ -n "$output" ] && echo "$output" >&2
          # Log the error. The caller decides whether to exit.
          write_message $LOG_LEVEL_ERROR "${command} on ${_host} failed with err: ${exit_status}"
          return $exit_status
    fi

    # Print output if VERBOSE is enabled
    if [ "$VERBOSE" -eq 1 ] && [ -n "$output" ]; then
      echo "$output"
    fi

    debug "finished exec_c ${command}";
    return 0
}

function write_message() {
  local _level="$1"
  local _message="$2"
  # Optional exit code
  local _exitCode="${3:--1}"

  # Validate exit code
  if ! [[ "$_exitCode" =~ ^-*[0-9]+$ ]]; then
    _exitCode="-1"
  fi

  # Handle verbosity levels
  [ "$DEBUG" -eq 0 ] && [ "$_level" = "$LOG_LEVEL_DEBUG" ] && return 0
  [ "$VERBOSE" -eq 0 ] && [ "$DEBUG" -eq 0 ] && [ "$_level" = "$LOG_LEVEL_INFO" ] && return 0

  # Setup colors using tput if available
  local _messagePrefix=""
  # Check if tput is available and terminal supports colors
  if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    local RED=$(tput setaf 1)
    local GREEN=$(tput setaf 2)
    local YELLOW=$(tput setaf 3)
    local BLUE=$(tput setaf 4)
    local BOLD=$(tput bold)
    local RESET=$(tput sgr0)

    [ "$_level" = "$LOG_LEVEL_DEBUG" ] && _messagePrefix="${BLUE}DEBUG:${RESET} "
    [ "$_level" = "$LOG_LEVEL_INFO" ] && _messagePrefix="${GREEN}INFO:${RESET} "
    [ "$_level" = "$LOG_LEVEL_WARNING" ] && _messagePrefix="${YELLOW}${BOLD}WARNING:${RESET} "
    [ "$_level" = "$LOG_LEVEL_ERROR" ] && _messagePrefix="${RED}${BOLD}ERROR:${RESET} "
  else
    [ "$_level" = "$LOG_LEVEL_DEBUG" ] && _messagePrefix="DEBUG: "
    [ "$_level" = "$LOG_LEVEL_INFO" ] && _messagePrefix="INFO: "
    [ "$_level" = "$LOG_LEVEL_WARNING" ] && _messagePrefix="WARNING: "
    [ "$_level" = "$LOG_LEVEL_ERROR" ] && _messagePrefix="ERROR: "
  fi

  # Print message
  local _timestamp=$( get_datetime "$TIME_FORMAT" )
  printf "%-17s %-15s %b%b\n" "$_timestamp" "[${MESSAGE_HEADER}]" "$_messagePrefix" "$_message"

  # Exit if needed
  if [ "$_exitCode" -ne -1 ]; then
    # Disable set -e before final exit
    set +e
    exit "$_exitCode"
  fi
}

function get_datetime() {
  date +"$1"
}

function debug() {
  write_message $LOG_LEVEL_DEBUG "${1:-$LOG_NO_MESSAGE}"
}

function info() {
  write_message $LOG_LEVEL_INFO "${1:-$LOG_NO_MESSAGE}"
}

function warning() {
  write_message $LOG_LEVEL_WARNING "${1:-$LOG_NO_MESSAGE}" >&2
}

# error_message exits the script
function error_message() {
  write_message $LOG_LEVEL_ERROR "${1:-"An error occurred"}" "${2:-101}" >&2
}

function checkBin() {
    local _binary="$1";
    if [ ! -x "$_binary" ]; then
        error_message "Binary '$_binary' not found or does not have execute permission." 102
    fi
}

function certValidate() {
    local cert_file=$1;
    local key_file=$2;

    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
      return 1
    fi

    # Check validity period (at least 24 hours left)
    if openssl x509 -checkend 86400 -noout -in "$cert_file" >/dev/null 2>&1; then
        # Check if modulus matches. We redirect stderr to /dev/null because openssl will complain if the key is encrypted and no password is provided.
        # This function assumes keys installed in PKI_DIR are decrypted.
        local cert_mod
        local key_mod

        if [[ "$cert_file" == *".pub" ]]; then
             # Handle public key comparison (e.g., sa.pub vs sa.key)
             cert_mod=$(openssl pkey -pubin -in "$cert_file" -noout -modulus 2>/dev/null)
        else
             cert_mod=$(openssl x509 -in "$cert_file" -noout -modulus 2>/dev/null)
        fi

        key_mod=$(openssl rsa -in "$key_file" -noout -modulus 2>/dev/null)

        if [ -n "$cert_mod" ] && [ -n "$key_mod" ] && [ "$cert_mod" == "$key_mod" ]; then
            return 0;
        fi
    fi
    return 1;
}

function get_host_ips() {
    info "starting get_host_ips";
    declare -A ips_host;
    # Portable IP address extraction
    local ip_proc="ip -4 addr show | grep inet | awk '{print \$2}' | cut -d/ -f1";

    local hostname=$(hostname);
    # Use mapfile to read IPs into array
    mapfile -t ips < <(eval $ip_proc)
    ips_host["${hostname}"]="${ips[*]}";

    if [ -f $config_yaml ]; then
        # Use .[]? to handle empty hosts list gracefully
        for host in $($YQ -r ".hosts | .[]?" $config_yaml); do
            if [ -n "$host" ]; then
              local remote_hostname=$($SSH_COMMAND "$host" hostname);
              mapfile -t remote_ips < <($SSH_COMMAND "$host" "${ip_proc}");
              ips_host["${remote_hostname}"]="${remote_ips[*]}";
            fi
        done
    fi

    # Generate hosts.yaml using yq for robust formatting
    local yaml_data=""
    for host in "${!ips_host[@]}"; do
        yaml_data+="${host}: ["
        local host_ips_str="${ips_host[$host]}"
        # Replace spaces with commas
        host_ips_str="${host_ips_str// /,}"
        yaml_data+="${host_ips_str}]\n"
    done

    echo -e "$yaml_data" | $YQ -P > "$hosts_yaml"

    info "finished get_host_ips";
}

function set_peer_ips() {
    info "starting set_peer_ips"

    if [ ! -e "$hosts_yaml" ]; then
      get_host_ips;
    fi

    if [ -z "$python" ]; then
        error_message "Python is required to determine peer IPs." 104
    fi

    # Python script to check if IP is in CIDR
    local py_ip="import ipaddress;import sys;print(1) if ipaddress.ip_address(sys.argv[2]) in ipaddress.ip_network(sys.argv[1]) else print(0)"
    local cidr=$($YQ -r ".controlPlaneSubnet" $config_yaml)

    # Clear previous entries
    peer_ips=()

    for host in $($YQ -r 'keys | .[]' $hosts_yaml); do
        for ip in $($YQ -r ".\"${host}\" | .[]" $hosts_yaml); do
            # Check if IP is in CIDR
            if [ "$($python -c "${py_ip}" "$cidr" "$ip")" -eq 1 ]; then
                # Exclude the Cluster VIP itself
                if [ "$ip" != "$CLUSTER_IP" ]; then
                    peer_ips["${host}"]=$ip;
                    # Assume one control-plane IP per host, break inner loop once found
                    break
                fi
            fi
        done
    done

    info "finished set_peer_ips"
}

function etcd_cluster_ips() {
    local cluster="";
    if [ ${#peer_ips[@]} -eq 0 ]; then
      set_peer_ips;
    fi

    for host in "${!peer_ips[@]}"; do
        cluster+="https://${peer_ips[$host]}:2379,";
    done
    cluster="${cluster::-1}";
    # Must echo the result for capture by caller
    echo "$cluster"
}

# Check binary permissions
checkBin "$YQ"
checkBin "$SED"
checkBin "$ssh"
checkBin "$scp"
checkBin "$python"
checkBin "$openssl"

# Check for root user
if ! isRootUser; then
  error_message "Script requires root privileges"
fi

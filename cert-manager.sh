#!/usr/bin/env bash
#
#MIT License
# ... (License text omitted for brevity) ...
#
# Doc:
#   Setups certificate authority with kubernetes intermediate certificate authorities for creating
#   kubernetes certificates.
#

_path=$(dirname "$0")
MESSAGE_HEADER="cert-manager";
# Source common.sh to enable strict mode and helper functions
source "${_path}/common.sh";

# These variables are modified by configureAlts and used by mkCert
dns_alts="";
ip_alts="";

function configureAlts() {
    local node_name=${1:-false};
    local is_host=${2:-false};
    info "starting configureAlts $node_name";

    local service_net_ip
    service_net_ip=$(${python} -c "import ipaddress;print(ipaddress.IPv4Network('${SERVICE_CIDR}')[1])")

    ip_alts="IP:127.0.0.1,IP:${CLUSTER_IP},IP:${service_net_ip}";
    dns_alts="DNS:localhost";

    info "starting configureAlts $node_name";

    local service_net_ip
    service_net_ip=$(${python} -c "import ipaddress;print(ipaddress.IPv4Network('${SERVICE_CIDR}')[1])")

    ip_alts="IP:127.0.0.1,IP:${CLUSTER_IP},IP:${service_net_ip}"
    dns_alts="DNS:localhost"

    if [ -f "$hosts_yaml" ]; then
        if [ "$is_host" != "false" ]; then
            # Specific node - only add IPs/names for that node
            for ip in $(yq_read ".\"${node_name}\".ips | .[]?" "$hosts_yaml"); do
                [[ -n "$ip" && "${ip}" != "127.0.0.1" ]] && ip_alts="${ip_alts},IP:${ip}"
            done

            # Add the full hostname
            dns_alts="${dns_alts},DNS:${node_name}"

            # Extract short hostname (e.g., 'bodes' from 'bodes.local.silverstars.io')
            local short_host="${node_name%%.*}"

            # Add short hostname with each domain suffix from hosts.yaml
            for domain in $(yq_read ".\"${node_name}\".domains | .[]?" "$hosts_yaml"); do
                [[ -n "$domain" ]] && dns_alts="${dns_alts},DNS:${short_host}${domain}"
            done
        else
            # All nodes (e.g., for kubernetes API server cert)
            for host in $(yq_read "keys | .[]?" "$hosts_yaml"); do
                [[ -z "$host" ]] && continue

                for ip in $(yq_read ".\"${host}\".ips | .[]?" "$hosts_yaml"); do
                    [[ -n "$ip" && "${ip}" != "127.0.0.1" ]] && ip_alts="${ip_alts},IP:${ip}"
                done

                dns_alts="${dns_alts},DNS:${host}"

                local short_host="${host%%.*}"
                for domain in $(yq_read ".\"${host}\".domains | .[]?" "$hosts_yaml"); do
                    [[ -n "$domain" ]] && dns_alts="${dns_alts},DNS:${short_host}${domain}"
                done
            done

            # Add kubernetes service DNS names using certs.yaml san.domains
            dns_alts="${dns_alts}"
            if [ -f "$CERTS_YAML" ]; then
                for domain in $(yq_read ".san.domains | .[]?" "$CERTS_YAML"); do
                    [[ -n "$domain"  ]] && dns_alts="${dns_alts},DNS:${node_name}${domain}"
                done
            fi
        fi
    fi

    info "finished configureAlts: ${ip_alts} ${dns_alts}";

}

function create_intermediate_ca() {
    local intermediate=$1;
    info "starting create_intermediate_ca $intermediate";

    # Define paths using CERT_DIR explicitly (absolute paths)
    # Ensure base_dir definition is correct for the intermediate CA's home
    local base_dir="${CERT_DIR}/${intermediate}"
    local key_file="${base_dir}/private/ca.key.pem";
    local csr_file="${base_dir}/csr/ca.csr.pem";
    local cert_file="${base_dir}/certs/ca.cert.pem";

    if [ -e "$cert_file" ]; then
        warning "OpenSSL create_intermediate_ca ${intermediate} CA already exists";
        return 0;
    fi

    exec_c "mkdir -p ${base_dir}"
    # Setup the intermediate CA directory structure and configuration
    pushd "${base_dir}" >/dev/null || { error_message "Failed to change directory to ${base_dir}" 1; return 1; }

    local inter_conf="${CERT_DIR}/intermediate-openssl.cnf";
    local ssl_conf="openssl.cnf" # Local config file name

    exec_c "mkdir -p certs crl csr newcerts private"
    exec_c "chmod 700 private"
    exec_c "touch index.txt"
    exec_c "echo 1000 > serial"
    # Prepare intermediate config file
    exec_c "cp $inter_conf $ssl_conf"
    # Customize the config for the specific intermediate CA
    exec_c "sed -i \"s/intermediate/$intermediate/g\" ${ssl_conf}"
    popd >/dev/null # Pop base_dir
    
    pushd "$CERT_DIR" >/dev/null || { error_message "Failed to change directory to ${CERT_DIR} for signing" 1; return 1; }

    info "creating ${intermediate} certificate authority";
    # Generate Intermediate CA Key (encrypted). Paths are absolute, CWD doesn't matter here.
    exec_c "openssl genrsa -aes256 -passout file:${PASS_FILE} -out ${key_file} 4096"
    exec_c "chmod 400 ${key_file}"

    local country=$(yq_read '.san.country ' "$CERTS_YAML");
    local state=$(yq_read '.san.state' "$CERTS_YAML");
    local locality=$(yq_read '.san.locality' "$CERTS_YAML");
    local email=$(yq_read '.san.email' "$CERTS_YAML");
    local subj="/C=${country}/ST=${state}/L=${locality}/O=kubernetes/OU=kubernetes/CN=${intermediate}-ca/emailAddress=${email}";

    # Create CSR for Intermediate CA
    # Use the config file located in the intermediate directory (absolute path)
    exec_c "openssl req -config ${base_dir}/openssl.cnf  \
          -key ${key_file} \
          -passin file:${PASS_FILE} -subj \"${subj}\" \
          -new -sha256 -out ${csr_file}"


    set +e
    exec_c "openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
          -days 3650 -notext -md sha256 \
          -in ${csr_file} \
          -batch -passin file:${PASS_FILE} \
          -out ${cert_file}"
    local sign_status=$?
    set -e

    popd >/dev/null # Pop CERT_DIR

    if [ $sign_status -ne 0 ]; then
        # Error message already printed by exec_c
        return 1
    fi

    exec_c "chmod 444 ${cert_file}"

    info "finished create_intermediate_ca $intermediate";
}

function mkCert() {
    local component=$1;
    local intermediate=$2;
    local cert_type=$3;
    local subj=$4;
    local icnf=$5; # Configuration file path (absolute path to temporary config)

    info "mkCert $component $intermediate $cert_type $subj";

    # Define paths using CERT_DIR explicitly (absolute paths)
    local base_dir="${CERT_DIR}/${intermediate}"
    local key_file="${base_dir}/private/${component}.key.pem";
    local csr_file="${base_dir}/csr/${component}.csr.pem";
    local cert_out="${base_dir}/certs/${component}.cert.pem";

    local alt_names=""
    if [ -n "${dns_alts}" ]; then
        alt_names="subjectAltName=${dns_alts}"
        if [ -n "${ip_alts}" ]; then
            alt_names="${alt_names},${ip_alts}";
        fi
    elif [ -n "${ip_alts}" ]; then
        alt_names="subjectAltName=${ip_alts}";
    fi

    pushd "$CERT_DIR" >/dev/null || { error_message "Failed to change directory to ${CERT_DIR} for signing" 1; return 1; }
    # Generate Key (unencrypted for component usage)
    exec_c "openssl genrsa -out \"$key_file\" 4096"
    exec_c "chmod 400 \"$key_file\""

    # Create CSR
    # Construct the command dynamically
    local openssl_cmd="openssl req -config \"${icnf}\" -key \"${key_file}\""
    openssl_cmd="${openssl_cmd} -subj \"${subj}\""
    if [ -n "${alt_names}" ]; then
        openssl_cmd="${openssl_cmd} -addext \"${alt_names}\""
    fi
    openssl_cmd="${openssl_cmd} -new -sha256 -out \"${csr_file}\""
    info "${openssl_cmd}";
    exec_c "${openssl_cmd}"

    local sign_conf="${base_dir}/openssl.cnf"

    openssl_cmd="openssl ca -config \"${sign_conf}\" -extensions \"${cert_type}\""

    openssl_cmd="${openssl_cmd} -days 1024 -notext -md sha256 -passin file:\"${PASS_FILE}\""

    openssl_cmd="${openssl_cmd} -in \"${csr_file}\" -batch -out \"${cert_out}\""

    info "${openssl_cmd}";


    set +e
    exec_c "${openssl_cmd}"
    local sign_status=$?
    set -e

    popd >/dev/null # Pop base_dir

    if [ $sign_status -ne 0 ]; then

        return 1
    fi

    exec_c "chmod 444 \"${cert_out}\""
}

function create_ca() {
    info "starting create_ca";
    # Paths relative to CERT_DIR
    local key_file="private/ca.key.pem";
    local cert_file="certs/ca.cert.pem";

    if [ -e "${CERT_DIR}/${cert_file}" ]; then
        warning "OpenSSL create_ca CA already exists";
        return 0; # Already exists, success
    fi

    [ ! -f "$SSL_CNF" ] && error_message "OpenSSL ${SSL_CNF} does not exist" 1
    [ ! -f "$INTER_SSL_CNF" ] && error_message "OpenSSL ${INTER_SSL_CNF} does not exist" 1

    local ssl_conf="${CERT_DIR}/openssl.cnf";
    local inter_conf="${CERT_DIR}/intermediate-openssl.cnf";
    # Use exec_c for robust execution
    exec_c "cp ${SSL_CNF} ${ssl_conf}"
    exec_c "cp ${INTER_SSL_CNF} ${inter_conf}"

    # PASS_FILE creation is handled in common.sh now.

    # Use pushd/popd for operations inside CERT_DIR, as openssl.cnf uses relative paths.
    pushd "$CERT_DIR" >/dev/null || { error_message "Failed to change directory to ${CERT_DIR}" 1; return 1; }

    exec_c "mkdir -p certs crl csr newcerts private"
    exec_c "chmod 700 private"
    exec_c "touch index.txt"
    exec_c "echo 1000 > serial"

    local country=$(yq_read '.san.country ' "$CERTS_YAML");
    local state=$(yq_read '.san.state' "$CERTS_YAML");
    local locality=$(yq_read '.san.locality' "$CERTS_YAML");
    local email=$(yq_read '.san.email' "$CERTS_YAML");
    local subj="/C=${country}/ST=${state}/L=${locality}/O=kubernetes/OU=silverstars.io/CN=ca/emailAddress=${email}";

    # Generate Root CA Key (encrypted)
    # PASS_FILE is absolute, key_file is relative.
    exec_c "openssl genrsa -aes256 -passout file:${PASS_FILE} -out ${key_file} 4096"
    exec_c "chmod 400 ${key_file}"
    # Generate Root CA Certificate
    # Note: We use the relative path 'openssl.cnf' for config as we are inside CERT_DIR
    exec_c "openssl req -config openssl.cnf -key ${key_file} -new -x509 -days 1810 \
    -passin file:${PASS_FILE} -subj \"${subj}\" -sha512 -extensions v3_ca -out ${cert_file}"

    popd >/dev/null
    info "finished create_ca";
}

function validate_cert_internal() {
    local component=$1;
    local intermediate=$2;

    info " start validate_cert_internal $component $intermediate";
    # Define paths using CERT_DIR explicitly
    local key_file="${CERT_DIR}/${intermediate}/private/${component}.key.pem";
    local cert_out="${CERT_DIR}/${intermediate}/certs/${component}.cert.pem";

    # Return 1 (failure/needs generation) if files don't exist
    if [ ! -e "$cert_out" ] || [ ! -e "$key_file" ]; then
        return 1;
    fi

    # Call certValidate and return its status.
    # We assume component keys generated by mkCert are unencrypted.
    certValidate "$cert_out" "$key_file"
    return $?
}

function certHandler() {
    local component=$1;
    local intermediate=$2;
    local cert_type=$3;
    local prefix=$4;
    info " start certHandler $component $intermediate $cert_type $prefix";

    # Check if cert exists and is valid
    if validate_cert_internal "$component" "$intermediate"; then
        warning "OpenSSL certHandler ${intermediate} ${component} already exists and is valid";
        return 0;
    fi

    # If not valid or doesn't exist, proceed to generate
    writeConfig "$component" "$intermediate" "$cert_type" "$prefix";
}

function writeConfig() {
    local component=$1;
    local intermediate=$2;
    local cert_type=$3;
    local prefix=$4;

    info "writeConfig $component $intermediate $cert_type $prefix";

    # Prepare a specific config file for this component generation (temporary)
    local icnf="${CERT_DIR}/${intermediate}/openssl-${component}.conf"
    local base_cnf="${CERT_DIR}/${intermediate}/openssl.cnf"

    if [ ! -f "$base_cnf" ]; then
        error_message "Base OpenSSL config not found: ${base_cnf}" 1
        return 1
    fi
    cp "$base_cnf" "$icnf"

    # Initialize variables
    local orgName="kubernetes"
    local cn=""  # Changed from cn_prefix to cn for clarity

    # Determine Organization Name (O)
    if [ "$cert_type" != "server_cert" ]; then
        orgName="$intermediate";
    fi

    # Configure Subject Alternative Names (SANs) and set O/CN for specific Kubernetes components
    if [[ "$prefix" == "system:masters" ]]; then
        configureAlts "$component" true
        orgName="${prefix}";
        cn="${component}";  # For masters, use component name directly
    elif [[ "$prefix" == "system:nodes" ]]; then
        configureAlts "$component" true
        orgName="${prefix}";
        cn="system:node:${component}";  # Required format for Node authorization
    elif [[ "$component" == "kube-proxy" ]]; then
        configureAlts $component true;
        orgName="system:node-proxier";  # Group for kube-proxy
        cn="system:kube-proxy";  # Standard name for kube-proxy
    elif [[ "$component" == "kube-scheduler" ]]; then
        configureAlts $component false;
        orgName="system:kube-scheduler";  # Correct group for scheduler
        cn="system:kube-scheduler";  # Standard name for scheduler
    elif [[ "$component" == "kube-controller-manager" ]]; then
        configureAlts $component false;
        orgName="system:kube-controller-manager";  # Correct group for controller-manager
        cn="system:kube-controller-manager";  # Standard name for controller-manager
    else
        configureAlts $component false;
        if [ -n "$prefix" ]; then
            orgName="${prefix}";
            # For other components, use the component name directly
            cn="${component}";
        else
            cn="${component}";
        fi
    fi

    local country=$(yq_read '.san.country ' "$CERTS_YAML");
    local state=$(yq_read '.san.state' "$CERTS_YAML");
    local locality=$(yq_read '.san.locality' "$CERTS_YAML");
    local email=$(yq_read '.san.email' "$CERTS_YAML");

    local subj="/C=${country}/ST=${state}/L=${locality}/O=${orgName}/OU=${intermediate}/CN=${cn}/emailAddress=${email}";

    mkCert "$component" "$intermediate" "$cert_type" "$subj" "$icnf";

    # Clean up temporary config file
    rm -f "$icnf"
}
# Helper functions to iterate YAML configuration
function create_server_certs() {
    info "starting create_server_certs";
    # Use .[]? to handle empty results gracefully
    for intermediate in $(yq_read ".certs.server | keys | .[]? " "$CERTS_YAML"); do
        if [ -n "$intermediate" ]; then
            for server in $(yq_read ".certs.server | .[\"${intermediate}\"] | .[]? " "$CERTS_YAML"); do
                if [ -n "$server" ]; then
                    local component="$server";
                    local prefix="";
                    if [[ "$server" == *";"* ]]; then
                        component=${server%;*};
                        prefix=${server#*;};
                    fi
                    certHandler "$component" "$intermediate" "server_cert" "$prefix";
                fi
            done
        fi
    done
    info "finished create_server_certs";
}

function create_host_certs() {
    info "starting create_host_certs";
    if [ ! -f "$hosts_yaml" ]; then
        warning "hosts.yaml not found, skipping host cert generation."
        return
    fi

    local intermediate="kubernetes";
    for host in $(yq_read "keys | .[]? " "$hosts_yaml"); do
        if [ -n "$host" ]; then
            local prefix="system:nodes";
            certHandler "$host" "$intermediate" "server_cert" "$prefix";
        fi
    done
    info "finished create_host_certs";
}

function create_client_certs() {
    info "starting create_client_certs";

    for intermediate in $(yq_read ".certs.client | keys | .[]? " "$CERTS_YAML"); do
        if [ -n "$intermediate" ]; then
            for client in $(yq_read ".certs.client | .[\"${intermediate}\"] | .[]? " "$CERTS_YAML"); do
                if [ -n "$client" ]; then
                    local component="$client";
                    local prefix="";
                    if [[ "$client" =~ ";" ]]; then
                        component=${client%;*};
                        prefix=${client#*;};
                    fi
                    certHandler "$component" "$intermediate" "usr_cert" "$prefix";
                fi
            done
        fi
    done
    info "finished create_client_certs";
}

function cleanup() {
    info "starting cleanup";
    rm -rf "$CERT_DIR";
}

function main() {
    info "starting main";
    # CLEAN status is passed via environment variable if called from proc.sh
    [ "$CLEAN" = "true" ] && cleanup;
    mkdir -p "$CERT_DIR";

    # Check if CERTS_YAML exists
    if [ ! -f "$CERTS_YAML" ]; then
        error_message "Certs configuration file not found: ${CERTS_YAML}" 1
        return 1
    fi

    create_ca;

    # Collect all unique intermediate CAs from both client and server sections
    declare -A intermediates
    for intermediate in $(yq_read ".certs.client | keys | .[]?" "$CERTS_YAML"); do
        if [ -n "$intermediate" ]; then
            intermediates["$intermediate"]=1
        fi
    done
    for intermediate in $(yq_read ".certs.server | keys | .[]?" "$CERTS_YAML"); do
        if [ -n "$intermediate" ]; then
            intermediates["$intermediate"]=1
        fi
    done

    # Create intermediate CAs
    for intermediate in "${!intermediates[@]}"; do
         create_intermediate_ca "$intermediate";
    done


    create_server_certs;
    create_client_certs;
    create_host_certs;
    info "finished main"
}

#create_host_certs;
main;

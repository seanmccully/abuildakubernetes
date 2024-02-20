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
#   Setups certificate authority with kubernetes intermediate certificate authorities for creating
#   kubernetes certificates.
#


_path=$(dirname "$0")
MESSAGE_HEADER="cert-manager";
source "${_path}/common.sh";

function create_ca() {
    info "starting create_ca";
    key_file="private/ca.key.pem";
    cert_file="certs/ca.cert.pem";

    if [ -e $cert_file ]; then
        warning "OpenSSL create_ca CA already exists";
        return 1;
    fi

    [ ! -f $SSL_CNF ] && error_message "OpenSSL ${SSL_CNF} does not exist";
    [ ! -f $INTER_SSL_CNF ] && error_message "OpenSSL ${INTER_SSL_CNF} does not exist";
    ssl_conf="${CERT_DIR}/openssl.cnf";
    inter_conf="${CERT_DIR}/intermediate-openssl.cnf";
    exec_c "cp ${SSL_CNF} ${ssl_conf}";
    exec_c "cp ${INTER_SSL_CNF} ${inter_conf}";

    exec_c "echo ${CA_PASS} > ${PASS_FILE}";
    exec_c "chmod 0400 ${PASS_FILE}";

    pushd $CERT_DIR;
    exec_c "mkdir certs crl csr newcerts private";
    exec_c "chmod 700 private"
    exec_c "touch index.txt"
    exec_c "echo 1000 > serial";

    country=$($YQ -r '.san.country ' $CERTS_YAML);
    state=$($YQ -r '.san.state' $CERTS_YAML);
    locality=$($YQ -r '.san.locality' $CERTS_YAML);
    email=$($YQ -r '.san.email' $CERTS_YAML);
    subj="/C=$country/ST=$state/L=$locality/O=kubernetes/OU=kubernetes/CN=ca/emailAddress=$email";

    exec_c "openssl genrsa -aes256 -passout file:${PASS_FILE} -out ${key_file} 4096"
    exec_c "chmod 400 ${key_file}"
    exec_c "openssl req -config ${ssl_conf} -key ${key_file} -new -x509 -days 1810 \
    -passin file:${PASS_FILE} -subj ${subj} -sha512 -extensions v3_ca -out ${cert_file}"
    popd;
    info "finished create_ca";
}

function create_intermediate_ca() {

    intermediate=$1;
    info "starting create_intermediate_ca $intermediate";

    key_file="${intermediate}/private/${intermediate}.key.pem";
    csr_file="${intermediate}/csr/${intermediate}.csr.pem";
    cert_file="${intermediate}/certs/${intermediate}.cert.pem";

    if [ -e $cert_file ]; then
        warning "OpenSSL create_intermediate_ca ${intermediate} CA already exists";
        return 1;
    fi

    exec_c "mkdir ${CERT_DIR}/${intermediate}";
    pushd "${CERT_DIR}/${intermediate}";

    inter_conf="${CERT_DIR}/intermediate-openssl.cnf";
    ssl_conf="openssl.cnf"

    exec_c "mkdir certs crl csr newcerts private";
    exec_c "chmod 700 private";
    exec_c "touch index.txt";
    exec_c "echo 1000 > serial";
    exec_c "cp $inter_conf $ssl_conf"
    exec_c "sed -i \"s/intermediate/$intermediate/g\" ${ssl_conf}";
    popd;
    info "creating ${intermediate} certificate authority";
    exec_c "openssl genrsa -aes256 -passout file:${PASS_FILE} -out ${key_file} 4096"
    exec_c "chmod 400 ${key_file}";

    country=$($YQ -r '.san.country ' $CERTS_YAML);
    state=$($YQ -r '.san.state' $CERTS_YAML);
    locality=$($YQ -r '.san.locality' $CERTS_YAML);
    email=$($YQ -r '.san.email' $CERTS_YAML);
    subj="/C=$country/ST=$state/L=$locality/O=kubernetes/OU=kubernetes/CN=${intermediate}-ca/emailAddress=$email";

    exec_c "openssl req -config ${intermediate}/openssl.cnf  \
          -key ${key_file} \
          -passin file:${PASS_FILE} -subj ${subj} \
          -new -sha256 -out ${csr_file}"

    exec_c "openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
          -days 3650 -notext -md sha256 \
          -in ${csr_file} \
          -batch -passin file:${PASS_FILE} \
          -out ${cert_file}"
    exec_c "chmod 444 ${cert_file}"

    info "finished create_intermediate_ca $intermediate";
}

function validate_cert() {

    component=$1;
    intermediate=$2;
    cert_type=$3;
    prefix=$4;

    info " start validate_cert $component $intermediate $cert_type $prefix";
    key_file="${intermediate}/private/${component}.key.pem";
    csr_file="${intermediate}/csr/${component}.csr.pem";
    cert_out="${intermediate}/components/${component}.component.pem";

    [[ -e $cert_out && -e $key_file ]] || return 0;
    return certValidate $cert_out $key_file;
}

function certHandler() {
    component=$1;
    intermediate=$2;
    cert_type=$3;
    prefix=$4;
    info " start certHandler $component $intermediate $cert_type $prefix";
    if [ -e "${intermediate}/certs/${cert}.cert.pem" ]; then
        validate_cert $component $intermediate $cert_type $prefix;
        if [ $? == 0 ]; then
            warning "OpenSSL certHandler ${intermediate} ${component} already exists";
            return 1;
        fi
    fi
    writeConfig $component $intermediate $cert_type $prefix;
}

function writeHosts() {

    icnf=$1;
    node_name=${2:-false};
    info "writeHosts $icnf $node_name";
    if [ $node_name != false ]; then
        c=2;
        for ip in $($YQ -r ".${node_name} | .[]" $hosts_yaml); do
            echo "IP.${c} = ${ip}" >> $icnf;
            c=$[$c + 1];
        done
        c=2;
        echo "DNS.${c} = ${node_name}" >> $icnf;
        for domains in $($YQ -r '.san.domains |  .[] ' $CERTS_YAML); do
            c=$[$c + 1];
            echo "DNS.${c} = ${node_name}${domains}" >> $icnf;
        done
    else
        c=2;
        for host in $($YQ -r "keys | .[]" $hosts_yaml); do
            for ip in $($YQ -r ".${host} | .[]" $hosts_yaml); do
                echo "IP.${c} = ${ip}" >> $icnf;
                c=$[$c + 1];
            done
        done
        c=2;
        for host in $($YQ -r "keys | .[]" $hosts_yaml); do
            echo "DNS.${c} = ${host}" >> $icnf;
            for domains in $($YQ -r ".san.domains |  .[] " $CERTS_YAML); do
                c=$[$c + 1];
                echo "DNS.${c} = ${host}${domains}" >> $icnf;
            done
        done
    fi
}

function writeConfig() {

    component=$1;
    intermediate=$2;
    cert_type=$3;
    prefix=$4;

    info "writeConfig $component $intermediate $cert_type $prefix";
    icnf="$intermediate/openssl.conf"
    cp $intermediate/openssl.cnf $icnf;

    if [ $cert_type = "server_cert" ]; then
    cat <<- EOF >> "${icnf}"
[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

        exec_c "sed -i \"s/#subjectAltName/subjectAltName/g\" ${icnf}";
        exec_c "sed -i \"s/#req_extensions/req_extensions/g\" ${icnf}";
    else
        orgName="$intermediate";
    fi

    if [[ $prefix == "system:nodes" ]]; then
        writeHosts $icnf $component;
        orgName="${prefix}";
        cn_prefix="${prefix%*s}:";
    elif [[ $prefix == "system:node-proxier" ]]; then
        writeHosts $icnf $component;
        orgName="${prefix}";
        info "orgName ${orgName}";
        cn_prefix="${prefix%node-proxier}";
    else
        writeHosts $icnf;
        if [ ! -z "$prefix" ]; then
            orgName="${prefix}";
            cn_prefix="${prefix%:*}:";
        else
            orgName="${intermediate}";
        fi
    fi


    country=$($YQ -r '.san.country ' $CERTS_YAML);
    state=$($YQ -r '.san.state' $CERTS_YAML);
    locality=$($YQ -r '.san.locality' $CERTS_YAML);
    email=$($YQ -r '.san.email' $CERTS_YAML);

    subj="/C=${country}/ST=${state}/L=${locality}/O=${orgName}/OU=${intermediate}/CN=${cn_prefix}${component}/emailAddress=${email}";

    mkCert $component $intermediate $cert_type $subj;
}

function mkCert() {

    component=$1;
    intermediate=$2;
    cert_type=$3;
    subj=$4;
    info "mkCert $component $intermediate $cert_type $subj";

    icnf="${intermediate}/openssl.conf";
    key_file="${intermediate}/private/${component}.key.pem";
    csr_file="${intermediate}/csr/${component}.csr.pem";
    cert_out="${intermediate}/certs/${component}.cert.pem";

    if [ -e $cert_out ]; then
        warning "OpenSSL mkCert ${cert_out} already exists";
        return 1;
    fi

    exec_c "openssl genrsa -out $key_file 4096";
    exec_c "chmod 400 $key_file";
    exec_c "openssl req -config ${icnf} \
        -key ${key_file} \
        -subj "${subj}" \
        -new -sha256 -out ${csr_file}";

    exec_c "openssl ca -config ${icnf} \
      -extensions ${cert_type} -days 1024 -notext -md sha256 \
      -passin file:${PASS_FILE} \
      -in ${csr_file} \
      -batch \
      -out ${cert_out}";
    exec_c "chmod 444 ${cert_out}";
}

function create_server_certs() {
    info "starting create_server_certs";
    for intermediate in $($YQ -r ".certs.server | keys | .[] " $CERTS_YAML); do
        for server in $($YQ -r ".certs.server | .[\"${intermediate}\"] | .[] " $CERTS_YAML); do
            component=$server;
            prefix="";
            if [[ $server == *";"* ]]; then
                component=${server%;*};
                prefix=${server#*;};
            fi
            certHandler $component $intermediate "server_cert" $prefix;
        done
    done
    info "finished create_server_certs";
}

function create_host_certs() {

    info "starting create_host_certs";
    intermediate="kubernetes";
    for host in $($YQ -r "keys | .[] " $hosts_yaml); do
        prefix="system:nodes";
        certHandler $host $intermediate "server_cert" $prefix;
    done
    info "finished create_host_certs";
}

function create_client_certs() {

    info "starting create_client_certs";
    for intermediate in $($YQ -r ".certs.client | keys | .[] " $CERTS_YAML); do
        for client in $($YQ -r ".certs.client | .[\"${intermediate}\"] | .[] " $CERTS_YAML); do
            component=$client;
            prefix="";
            if [[ $client =~ ";" ]]; then
                component=${client%;*};
                prefix=${client#*;};
            fi
            certHandler $component $intermediate "usr_cert" $prefix;
        done
    done
    info "finished create_client_certs";
}

function cleanup() {
    info "starting cleanup";
    rm -rf $CERT_DIR;
}

function main() {

    info "starting main";
    #cleanup;
    mkdir -p $CERT_DIR;
    cd $CERT_DIR;

    create_ca;
    for intermediate in $($YQ -r ".certs.client | keys | .[]" $CERTS_YAML); do
        create_intermediate_ca $intermediate;
    done

    create_server_certs;
    create_client_certs;
    create_host_certs;
    info "finished main"
}


main;

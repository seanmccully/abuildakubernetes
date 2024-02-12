#!/usr/bin/env sh
#
# Setups Kubernetes, ETCD, GO and Calico source directories to build and deploy a kubernetes cluster
#

_path=$(dirname "$0")
MESSAGE_HEADER="source-builder";
source "${_path}/common.sh";


function clone_repo() {
    url=$1;
    info "starting clone_repo $url"
    exec_c "${git} clone ${url} && return 0";
}

function go_build() {
    info "starting go_build";
    exec_c "cd src/";
    exec_c "./clean.bash";
    exec_c "./all.bash";
    exec_c "cd ../";
    goroot=$(pwd);

    export GOBIN="${goroot}/bin";
    export GOROOT="${goroot}";
    export PATH="${goroot}/bin:${PATH}";
}

function golangci_build() {
    info "starting golangci_build";
    exec_c "bash ./install.sh -b /usr/local/bin";
}

function etcd_build() {
    info "starting etcd_build";
    exec_c "make";
    exec_c "install -m755 ./bin/etcd* /usr/local/bin/";
}

function kube_build() {
    info "starting kube_build";
    make;
    exec_c "install -vDm 755 _output/bin/kube* /usr/bin/";
    exec_c "install -vdm 755 /etc/kubernetes/";
    exec_c "install -vdm 700 /etc/kubernetes/manifests";
}


function git_reset_pull() {

    info "starting git_reset_pull";

    origin=$(git remote show | head -n 1);
    head=$(git remote show origin | head -n 5 | sed -n '/HEAD branch/s/.*: //p');
    clean=$(git status | grep clean);

    [[ -z $clean ]] && exec_c "git reset --hard";
    exec_c "git pull --rebase ${origin} ${head}";
}

function cni_plugins_build() {

    info "starting cni_plugins_build";
    exec_c "./build_linux.sh";
    exec_c "mkdir -p /opt/cni/bin";
    exec_c "install -m755 ./bin/* /opt/cni/bin/";
}


function runc_build() {
    info "starting runc_build";
    exec_c "make clean";
    exec_c "make all";
    exec_c "install -m755 ./runc /usr/local/bin/runc";
    exec_c "install -m755 contrib/cmd/recvtty/recvtty /usr/local/bin/recvtty";
    exec_c "install -m755 contrib/cmd/seccompagent/seccompagent /usr/local/bin/seccompagent";
    # Install mandocs
    #mkdir -p /usr/local/share/man/man8;
    #install -m644 ./man/man8/runc*.8 /usr/local/share/man/man8/;
}

function containerd_build() {

    info "starting containerd_build"
    ctd_service_file="${SYSTEMD_SERVICE_PATH}/containerd.service";

    exec_c "make clean";
    exec_c "make";
    exec_c "mkdir -p /etc/containerd/certs.d";
    exec_c "install ./containerd.service ${ctd_service_file}";

    exec_c "install -m755 ./bin/* /usr/local/bin/";
    # Install mandocs
    #mkdir -p /usr/local/share/man/man8;
    #mkdir -p /usr/local/share/man/man5;
    #go-md2man -in ./docs/man/containerd-config.8.md -out ./docs/man/containerd-config.8
    #go-md2man -in ./docs/man/containerd-config.toml.5.md -out ./docs/man/containerd-config.toml.5
    # install -m644 ./docs/man/containerd-config.8 /usr/local/share/man/man8/
    # install -m644 ./docs/man/containerd-config.toml.5 /usr/local/share/man/man5/

}

function clone_src() {
    repo_url=$1;
    build_func=${2:-""};

    info "starting clone_src $repo_url $build_func";
    repo_dir=$(echo ${repo_url##*/} | sed "s/.git//");

    if [ -d $SRC_DIR ]; then
        src="$SRC_DIR/$repo_dir";
        echo "${src}"
        if [ -d  $src ]; then
            pushd $src;
            if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]; then
                git_reset_pull;
                [ -z "${build_func}" ] || $build_func;
                popd;
                return;
            else
                popd;
                rm -rf $src;
            fi
        fi
    fi
    mkdir -p $SRC_DIR;
    pushd $SRC_DIR;

    success=false;
    attempt_num=1;
    max_attempts=3;
    while [ $success = false ] && [ $attempt_num -le $max_attempts ]; do
        if clone_repo $repo_url; then
            success=true;
        else
            attempt_num=$(( attempt_num + 1 ))
        fi
    done
    if [ $success = true ]; then
        pushd $repo_dir;
        [ -z $build_func ] || $build_func;
        popd;
        popd;
    else
        error_message "Failed to clone repo ${repo_url}" 103
    fi
}

function keepalived_build() {


    [ ! -e ./configure  ] && ./autogen.sh;
    exec_c "./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --localstatedir=/var --runstatedir=/run --enable-json --enable-snmp --enable-snmp-rfcv3 --enable-bfd;"
    exec_c "make";
    exec_c "make install";

}

function helm_build() {


    exec_c "make"
    exec_c "make install";

}


function calico_build() {

    info "starting calico_build";

    CALICO_GIT_REVISION=$($git rev-parse --short HEAD);
    GIT_VERSION=$($git describe --tags --dirty --always --abbrev=12);
    exec_c "cd ./calicoctl";
    exec_c "mkdir -p ${CNI_CONF_DIR}";

    build_arch=$(uname -m);
    arch="amd64";
    if [[ $build_arch == 'x86_64' ]]; then
        arch="aarch64";
    fi
    exec_c "rm ./bin/calicoctl-linux-${arch} || echo true";
    go build -o  bin/calicoctl-linux-$arch -buildvcs=false -ldflags "-X github.com/projectcalico/calico/calicoctl/calicoctl/commands.VERSION=${GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands.GIT_REVISION=${CALICO_GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands/common.VERSION=${GIT_VERSION} \
        -X main.VERSION=${GIT_VERSION}" ./calicoctl/calicoctl.go
    install -m755 ./bin/calicoctl-linux-$arch /usr/local/bin/calicoctl;
    cd ../manifests;
    HELM="/usr/local/bin/helm" ./generate.sh;
    cd ../cni-plugin;
    exec_c "rm -rf ./bin/* || echo true";

    go build -o  bin/$arch/install -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}"  github.com/projectcalico/calico/cni-plugin/cmd/install
    go build -o  bin/$arch/calico -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}"  github.com/projectcalico/calico/cni-plugin/cmd/calico
    go build -o  bin/$arch/calico-ipam -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}"  github.com/projectcalico/calico/cni-plugin/cmd/calico
    exec_c "install -m755 ./bin/$arch/calico ${CNI_BIN_DIR}/calico";
    exec_c "install -m755 ./bin/$arch/calico-ipam ${CNI_BIN_DIR}/calico-ipam";
    root_fs=$(df -h  | grep -e "/$" | awk '{ print $1 }');
    etc_mount=$(df -h | grep etc | awk '{ print $1 }');
    opt_mount=$(df -h | grep opt | awk '{ print $1 }');
    # Let calico cni plugins install think we are in a docker container;
    exec_c "mkdir -p /host && mount ${root_fs} /host";
    [[ ! -z $etc_mount ]] && exec_c "mount $etc_mount /host/etc";
    [[ ! -z $opt_mount ]] && exec_c "mount $opt_mount /host/opt";

    # Not installing certs
    exec_c "./bin/$arch/install || echo true";
    [[ ! -z $etc_mount ]] && exec_c "umount -f /host/etc";
    [[ ! -z $opt_mount ]] && exec_c "umount -f /host/opt";
    exec_c "umount -f /host";

    info "finished calico_build";
}

function cleanup() {
    info "starting cleanup";
    rm -rf $SRC_DIR;
}

function main() {
    info "starting main";
    clone_src $GO "go_build";
    clone_src $GOLANGCI "golangci_build";
    clone_src $KUBE_DOCS;
    clone_src $CONTAINERD "containerd_build";
    clone_src $RUNC "runc_build";
    clone_src $ETCD "etcd_build";
    clone_src $KUBE "kube_build";
    clone_src $CNI_PLUGINS "cni_plugins_build";
    clone_src $KEEPALIVED "keepalived_build";
    clone_src $HELM "helm_build";
    clone_src $CALICO "calico_build";
    info "finished main";
}

main;

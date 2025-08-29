#!/usr/bin/env bash
#
#MIT License
# ... (License text omitted for brevity) ...
#
# Doc:
#   Setups Kubernetes, ETCD, GO and Calico source directories to build and deploy a kubernetes cluster
#

_path=$(dirname "$0")
MESSAGE_HEADER="source-builder";
source "${_path}/common.sh";


function clone_repo() {
    local url=$1;
    info "starting clone_repo $url"
    # exec_c now returns status, allowing retry logic in clone_src to work.
    exec_c "${git} clone ${url}"
}

# Use pushd/popd as exec_c runs in a subshell
function go_build() {
    info "starting go_build";
    pushd src/ >/dev/null || { error_message "Failed to change directory to src" 1; return 1; }
    exec_c "./clean.bash"
    exec_c "./all.bash"
    popd >/dev/null

    local goroot
    goroot=$(pwd);

    export GOBIN="${goroot}/bin";
    export GOROOT="${goroot}";
    export PATH="${goroot}/bin:${PATH}";
}

function golangci_build() {
    info "starting golangci_build";
    exec_c "bash ./install.sh -b /usr/local/bin"
}

function etcd_build() {
    info "starting etcd_build";
    exec_c "make"
    exec_c "install -m755 ./bin/etcd* /usr/local/bin/"
}

function kube_build() {
    info "starting kube_build";
    exec_c "make"
    # Ensure destination directories exist before installing files
    exec_c "install -vdm 755 /usr/bin/"
    exec_c "install -vDm 755 _output/bin/kube* /usr/bin/"
    exec_c "install -vdm 755 /etc/kubernetes/"
    exec_c "install -vdm 700 /etc/kubernetes/manifests"
}


function git_reset_pull() {
    info "starting git_reset_pull";

    local origin="origin"
    # Check if 'origin' exists, otherwise use the first remote found
    if ! git remote show | grep -q "^${origin}$"; then
        origin=$(git remote show | head -n 1);
    fi

    if [ -z "$origin" ]; then
        warning "No git remote found."
        return 1
    fi

    # Fetch updates
    git fetch "$origin" >/dev/null 2>&1 || warning "Failed to fetch $origin"

    # Determine HEAD branch
    local head
    head=$(git remote show "$origin" | sed -n '/HEAD branch/s/.*: //p' | head -n 1);

    if [ -z "$head" ]; then
        # Fallback to current branch if remote HEAD detection fails
        head=$(git rev-parse --abbrev-ref HEAD)
        warning "Could not determine remote HEAD branch, using current branch $head."
    fi

    # Use git status --porcelain for script-friendly status check
    if [[ -n $(git status --porcelain) ]]; then
        exec_c "git reset --hard"
    fi

    exec_c "git pull --rebase ${origin} ${head}"
}

function cni_plugins_build() {
    info "starting cni_plugins_build";
    exec_c "./build_linux.sh"
    exec_c "mkdir -p /opt/cni/bin"
    exec_c "install -m755 ./bin/* /opt/cni/bin/"
}


function runc_build() {
    info "starting runc_build";
    exec_c "make clean"
    exec_c "make all"
    exec_c "install -m755 ./runc /usr/local/bin/runc"
    exec_c "install -m755 contrib/cmd/recvtty/recvtty /usr/local/bin/recvtty"
    exec_c "install -m755 contrib/cmd/seccompagent/seccompagent /usr/local/bin/seccompagent"
}

function cri_tools_build() {
    exec_c "make clean"
    exec_c "make && make install"
}

function containerd_build() {
    info "starting containerd_build"
    local ctd_service_file="${SYSTEMD_SERVICE_PATH}/containerd.service";

    exec_c "make clean"
    exec_c "make"
    exec_c "mkdir -p /etc/containerd/certs.d"

    if [ -f "./containerd.service" ]; then
      exec_c "install ./containerd.service ${ctd_service_file}"
    else
      warning "containerd.service file not found in source."
    fi

    exec_c "install -m755 ./bin/* /usr/local/bin/"
}

function clone_src() {
    local repo_url=$1;
    local build_func=${2:-""};

    info "starting clone_src $repo_url $build_func";
    local repo_dir
    repo_dir=$(basename "$repo_url" .git);

    mkdir -p "$SRC_DIR"
    local src="$SRC_DIR/$repo_dir";

    if [ -d "$src" ]; then
        pushd "$src" >/dev/null || { error_message "Failed to change directory to ${src}" 1; return 1; }
        if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]; then
            info "Repository exists, updating..."
            git_reset_pull;
            [ -z "${build_func}" ] || $build_func;
            popd >/dev/null
            return;
        else
            popd >/dev/null
            warning "Directory $src exists but is not a git repository. Removing."
            rm -rf "$src";
        fi
    fi

    pushd "$SRC_DIR" >/dev/null || { error_message "Failed to change directory to ${SRC_DIR}" 1; return 1; }

    # Retry logic
    local success=false;
    local attempt_num=1;
    local max_attempts=3;
    while [ "$success" = false ] && [ $attempt_num -le $max_attempts ]; do
        if clone_repo "$repo_url"; then
            success=true;
        else
            warning "Failed to clone repo ${repo_url}, attempt ${attempt_num} of ${max_attempts}"
            attempt_num=$(( attempt_num + 1 ))
            sleep 5
        fi
    done

    if [ "$success" = true ]; then
        pushd "$repo_dir" >/dev/null || { error_message "Failed to change directory to ${repo_dir}" 1; return 1; }
        [ -z "$build_func" ] || $build_func;
        popd >/dev/null # pop repo_dir
        popd >/dev/null # pop SRC_DIR
    else
        popd >/dev/null # pop SRC_DIR
        error_message "Failed to clone repo ${repo_url} after ${max_attempts} attempts" 103
    fi
}

function keepalived_build() {
    # Check if configure needs generating
    if [ ! -e ./configure ] && [ -f ./autogen.sh ]; then
       exec_c "./autogen.sh";
    fi

    if [ -f "./configure" ]; then
        exec_c "./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --localstatedir=/var --runstatedir=/run --enable-json --enable-snmp --enable-snmp-rfcv3 --enable-bfd;"
        exec_c "make"
        exec_c "make install"
    else
        warning "Keepalived configure script not found."
    fi
}

function helm_build() {
    exec_c "make"
    exec_c "make install"
}


function calico_build() {
    info "starting calico_build";

    local CALICO_GIT_REVISION
    CALICO_GIT_REVISION=$($git rev-parse --short HEAD);
    # Define CALICO_GIT_VERSION as it's used in ldflags
    local CALICO_GIT_VERSION=$CALICO_GIT_REVISION
    local GIT_VERSION
    GIT_VERSION=$($git describe --tags --dirty --always --abbrev=12);

    # Use pushd/popd
    pushd ./calicoctl >/dev/null || { error_message "Failed to change directory to ./calicoctl" 1; return 1; }
    exec_c "mkdir -p ${CNI_CONF_DIR}"

    # Determine architecture (Go convention: amd64, arm64)
    local build_arch
    build_arch=$(uname -m);
    local arch="amd64";

    # Fixed architecture logic
    case "$build_arch" in
        x86_64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            warning "Architecture $build_arch might not be fully supported, defaulting to amd64."
            ;;
    esac

    exec_c "rm -f ./bin/calicoctl-linux-${arch} || true"

    # Assuming 'go' is in PATH from go_build
    go build -v -o  bin/calicoctl-linux-$arch -buildvcs=false -ldflags "-X github.com/projectcalico/calico/calicoctl/calicoctl/commands.VERSION=${GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands.GIT_REVISION=${CALICO_GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands/common.VERSION=${GIT_VERSION} \
        -X main.VERSION=${GIT_VERSION}" ./calicoctl/calicoctl.go
    install -m755 ./bin/calicoctl-linux-$arch /usr/local/bin/calicoctl;
    popd >/dev/null

    pushd ./manifests >/dev/null || { error_message "Failed to change directory to ./manifests" 1; return 1; }
    if [ -x "/usr/local/bin/helm" ]; then
      HELM="/usr/local/bin/helm" ./generate.sh;
    else
      warning "Helm not found, skipping manifest generation."
    fi
    popd >/dev/null

    pushd ./cni-plugin >/dev/null || { error_message "Failed to change directory to ./cni-plugin" 1; return 1; }
    exec_c "rm -rf ./bin/* || true"

    # Fixed paths for go build commands
    go build -o  bin/$arch/install -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}"  ./cmd/install
    go build -o  bin/$arch/calico -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}"  ./cmd/calico
    # Fixed command path for calico-ipam
    go build -o  bin/$arch/calico-ipam -v -buildvcs=false -ldflags "-X main.VERSION=${GIT_VERSION}" ./cmd/calico-ipam

    exec_c "install -m755 ./bin/$arch/calico ${CNI_BIN_DIR}/calico"
    exec_c "install -m755 ./bin/$arch/calico-ipam ${CNI_BIN_DIR}/calico-ipam"

    # Improved mount handling for CNI installation simulation (if required by the installer)
    # This approach is inherently risky but preserved as it seems intentional.
    local root_fs
    root_fs=$(df -P / | tail -1 | awk '{ print $1 }');
    local etc_mount
    etc_mount=$(df -P /etc | tail -1 | awk '{ print $1 }');
    local opt_mount
    opt_mount=$(df -P /opt | tail -1 | awk '{ print $1 }');

    exec_c "mkdir -p /host"
    # Check if already mounted
    if ! mountpoint -q /host; then
      exec_c "mount ${root_fs} /host"
    fi

    # Mount /etc and /opt if they are separate mounts
    if [[ "$etc_mount" != "$root_fs" ]] && ! mountpoint -q /host/etc; then
        exec_c "mount $etc_mount /host/etc"
    fi

    if [[ "$opt_mount" != "$root_fs" ]] && [[ "$opt_mount" != "$etc_mount" ]] && ! mountpoint -q /host/opt; then
        exec_c "mount $opt_mount /host/opt"
    fi

    # Run installer (ignoring errors as per original script)
    exec_c "./bin/$arch/install || true"

    # Clean up mounts
    if mountpoint -q /host/opt; then exec_c "umount -f /host/opt"; fi
    if mountpoint -q /host/etc; then exec_c "umount -f /host/etc"; fi
    if mountpoint -q /host; then exec_c "umount -f /host"; fi

    popd >/dev/null

    info "finished calico_build";
}

function cleanup() {
    info "starting cleanup";
    rm -rf "$SRC_DIR";
}

function main() {
    info "starting main";
    [ "$CLEAN" = "true" ] && cleanup;
    clone_src "$GO" "go_build";
    clone_src "$GOLANGCI" "golangci_build";
    clone_src "$KUBE_DOCS";
    clone_src "$CONTAINERD" "containerd_build";
    clone_src "$RUNC" "runc_build";
    clone_src "$ETCD" "etcd_build";
    clone_src "$KUBE" "kube_build";
    clone_src "$CNI_PLUGINS" "cni_plugins_build";
    clone_src "$KEEPALIVED" "keepalived_build";
    clone_src "$CRITOOLS" "cri_tools_build";
    clone_src "$HELM" "helm_build";
    clone_src "$CALICO" "calico_build";
    info "finished main";
}

main;

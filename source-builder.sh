#!/usr/bin/env bash
#
#MIT License
# ... (License text omitted for brevity) ...
#
# Doc:
#   Setups Kubernetes, ETCD, GO and Calico source directories to build and deploy a kubernetes cluster
#
set -x;
_path=$(dirname "$0")
MESSAGE_HEADER="source-builder";
source "${_path}/common.sh";


function clone_repo() {
    local url=$1;
    # Accept optional second argument for the branch
    local branch=${2:-""};
    info "starting clone_repo $url"

    local clone_opts=""
    if [ -n "${branch}" ]; then
        clone_opts="--branch ${branch}"
        info "Cloning with options: ${clone_opts}"
    fi

    # exec_c now returns status, allowing retry logic in clone_src to work.
    # Add the clone options to the command
    exec_c "${git} clone ${clone_opts} ${url}"
}

# Use pushd/popd as exec_c runs in a subshell
function go_build() {
    info "starting go_build";
    exec_c "git checkout release-branch.go1.25"
    pushd src/ >/dev/null || { error_message "Failed to change directory to src" 1; return 1; }
    exec_c "./clean.bash" || true;
    exec_c "./make.bash"
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


# Updated to accept an optional branch and robustly align local state with the remote branch.
function git_reset_pull() {
    # Accept optional specified branch
    local specified_branch=${1:-""}
    info "starting git_reset_pull. Specified branch: '${specified_branch}'";

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
    # Improved error handling for fetch
    if ! git fetch "$origin" >/dev/null 2>&1; then
        warning "Failed to fetch $origin. Cannot update."
        return 1
    fi

    local target_branch

    if [ -n "$specified_branch" ]; then
        target_branch="$specified_branch"
    else
        # Determine current branch assume HEAD, or previously select `specified_branch`
        target_branch=$(git branch | grep \* | awk '{ print $2  }');
        if [ -z "$target_branch" ]; then
            # Fallback logic if remote HEAD detection fails.
            # If we cannot determine the remote HEAD, we cannot safely proceed with the default behavior.
            warning "Could not determine remote HEAD branch. Cannot safely update."
            return 1
        fi
    fi

    # Ensure the working directory is clean before potentially switching branches or resetting state.
    # Use git status --porcelain for script-friendly status check
    if [[ -n $(git status --porcelain) ]]; then
        info "Discarding local changes."
        exec_c "git reset --hard"
    fi

    # Align local state with the remote target branch.
    # We use 'git checkout -B <branch> <start-point>'
    # This creates the branch if it doesn't exist, or resets it if it does, pointing it to the start-point (origin/target_branch).
    # This is more robust for build scripts than git pull --rebase.
    info "Aligning local repository with $origin/$target_branch"
    if ! exec_c "git checkout -B $target_branch $origin/$target_branch"; then
        # If this fails, the branch likely doesn't exist on the remote.
        if [ -n "$specified_branch" ]; then
            # If the user specifically requested this branch, we must fail.
            error_message "Failed to find or checkout requested branch '$specified_branch' from $origin." 1
        else
            # If the default branch failed, something is wrong with the repo.
            error_message "Failed to checkout default branch '$target_branch' from $origin." 1
        fi
        return 1
    fi

    return 0 # Success
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
    if [ -f "./contrib/cmd/memfd-bind/memfd-bind" ]; then
    exec_c "install -m755 contrib/cmd/memfd-bind/memfd-bind /usr/local/bin/memfd-bind";
    fi
	if [ -f "./contrib/completions/bash/runc" ]; then
    exec_c "install -m755 contrib/completions/bash/runc /usr/share/bash-completion/completions/"; 
	fi
}

function cri_tools_build() {
    exec_c "make clean"
    exec_c "make && make install"
}

function containerd_build() {
    info "starting containerd_build"
    local ctd_service_file="${SYSTEMD_SERVICE_PATH}/containerd.service";

    exec_c "make clean"
    exec_c "CGO_ENABLED=1 make"
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
    # New optional argument for branch name
    local branch=${3:-""};

    info "starting clone_src $repo_url $build_func ${branch}";
    local repo_dir
    repo_dir=$(basename "$repo_url" .git);

    mkdir -p "$SRC_DIR"
    local src="$SRC_DIR/$repo_dir";

    if [ -d "$src" ]; then
        pushd "$src" >/dev/null || { error_message "Failed to change directory to ${src}" 1; return 1; }
        if [[ $(git rev-parse --is-inside-work-tree 2> /dev/null) ]]; then
            info "Repository exists, updating..."
            # Pass the branch name and handle potential failure
            if ! git_reset_pull "$branch"; then
                # Error already reported by git_reset_pull.
                warning "Skipping build due to update failure."
                popd >/dev/null
                # Return success so the script continues with other components
                return 0;
            fi

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
        # Pass the branch name to clone_repo
        if clone_repo "$repo_url" "$branch"; then
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
    # Ensure 'git' command is available
    if [ -z "$git" ]; then
        if ! command -v git >/dev/null 2>&1; then
            error_message "Git command not found. Cannot determine Calico version." 1
            return 1
        fi
        git="git"
    fi

    CALICO_GIT_REVISION=$($git rev-parse --short HEAD);
    # Define CALICO_GIT_VERSION as it's used in ldflags
    local CALICO_GIT_VERSION=$CALICO_GIT_REVISION
    local GIT_VERSION
    GIT_VERSION=$($git describe --tags --dirty --always --abbrev=12);

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

    # 1. Build calicoctl
    pushd ./calicoctl >/dev/null || { error_message "Failed to change directory to ./calicoctl" 1; return 1; }
    exec_c "mkdir -p ${CNI_CONF_DIR}"

    exec_c "rm -f ./bin/calicoctl-linux-${arch} || true"

    # Assuming 'go' is in PATH (e.g., from go_build)
    if ! command -v go >/dev/null 2>&1; then
        error_message "Go compiler not found in PATH. Cannot build Calico." 1
        popd >/dev/null
        return 1
    fi

    go build -v -o  bin/calicoctl-linux-$arch -buildvcs=false -ldflags "-X github.com/projectcalico/calico/calicoctl/calicoctl/commands.VERSION=${GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands.GIT_REVISION=${CALICO_GIT_VERSION} \
        -X github.com/projectcalico/calico/calicoctl/calicoctl/commands/common.VERSION=${GIT_VERSION} \
        -X main.VERSION=${GIT_VERSION}" ./calicoctl/calicoctl.go
    install -m755 ./bin/calicoctl-linux-$arch /usr/local/bin/calicoctl;
    popd >/dev/null

    # 2. Generate Manifests
    pushd ./manifests >/dev/null || { error_message "Failed to change directory to ./manifests" 1; return 1; }
    # Use command -v directly to find helm
    HELM_C=$(command -v helm); 
    if [ -x "$HELM_C" ]; then
      # This relies on etcd_cluster_ips being defined/sourced (e.g., from common.sh or similar)
      local cluster=etcd_cluster_ips; 

      # Ensure YQ is available
      if [ -z "$YQ" ] || [ ! -x "$YQ" ]; then
          warning "YQ utility not found or not executable. Skipping manifest customization."
      else
          val_yml="../charts/calico/values.yaml";
          local etcd_cert=$(cat "${CERTS_DIR}/etcd/certs/kube-etcd-peer.cert.pem")
          local etcd_key=$(cat "${CERT_DIR}/etcd/private/kube-etcd-peer.key.pem")
          local etcd_ca=$(cat "${CERT_DIR}/etcd/certs/etcd.cert.pem")
          yq_write '.datastore="etcd"' $val_yml
          yq_write '.etcd.tls.crt = $val' "$chart_values" "$etcd_cert"
          yq_write '.etcd.tls.key = $val' "$chart_values" "$etcd_key"
          yq_write '.etcd.tls.ca = $val' "$chart_values" "$etcd_ca"
          yq_write '.network="calico"' $val_yml
          yq_write '.bpf=true' $val_yml
          yq_write '.includeCRDs=false' $val_yml

          yq_write ".etcd.endpoints=\"${cluster}\"" $val_yml
          yq_write ".tigeraOperator.image=\"tigera\/operator\"" $val_yml
          yq_write ".tigeraOperator.registry=\"quay.io\"" $val_yml
          yq_write ".tigeraOperator.version=\"master\"" $val_yml
          # Ensure YQ and HELM paths are correctly passed if they are custom variables
          exec_c "YQ=\"${YQ}\" HELM=\"${HELM_C}\" ./generate.sh";
      fi
    else
      warning "Helm not found, skipping manifest generation."
    fi
    popd >/dev/null

    # 3. Build CNI Plugins (Directly, avoiding complex installer binary and mounts)
    
    # Ensure the output directory exists
    mkdir -p bin/$arch/

    info "Building Calico CNI plugins (calico, calico-ipam)"
    
    # Optional: Build calico-node if needed
    #CGO_ENABLED=1 GOEXPERIMENT=boringcrypto go build -o bin/$arch/calico-node -tags fipsstrict -v -buildvcs=false -ldflags "-X main.VERSION=$CALICO_GIT_VERSION" ./node/cmd/calico-node

    # Build 'calico' CNI plugin
    go build -o bin/$arch/calico -v -buildvcs=false -ldflags "-X main.VERSION=$CALICO_GIT_VERSION" ./cni-plugin/cmd/calico
    
    # Build 'calico-ipam' CNI plugin (Essential)
    go build -o bin/$arch/calico-ipam -v -buildvcs=false -ldflags "-X main.VERSION=$CALICO_GIT_VERSION" ./node/cmd/calico-ipam

    # We skip the 'install' binary as it requires complex environment setup (mounts) which proved unstable or impossible in restricted environments.
    # go build -o bin/$arch/install -v -buildvcs=false -ldflags "-X main.VERSION=$CALICO_GIT_VERSION" ./cni-plugin/cmd/install
    
    info "built calico cni commands";

    # 4. Install binaries directly to the CNI directory
    exec_c "mkdir -p ${CNI_BIN_DIR}"
    exec_c "install -m755 ./bin/$arch/calico ${CNI_BIN_DIR}/calico"
    exec_c "install -m755 ./bin/$arch/calico-ipam ${CNI_BIN_DIR}/calico-ipam"


    info "finished calico_build";
}

function cleanup() {
    info "starting cleanup";
    rm -rf "$SRC_DIR";
}

function main() {
    info "starting main";
    [ "$CLEAN" = "true" ] && cleanup;

    clone_src "$GO" "go_build" "release-branch.go1.25";
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

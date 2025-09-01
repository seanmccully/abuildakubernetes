#!/usr/bin/env bash
# /usr/local/bin/etcd-cluster-sync.sh
#
# Synchronizes ETCD startup across cluster nodes

SYNC_DIR="/var/lib/etcd-sync"
READY_FLAG="${SYNC_DIR}/ready"
TIMEOUT=30
CONFIG_YAML="/etc/etcd/etcd.conf.yml"  # Update this path

function prepare_sync() {
    mkdir -p "$SYNC_DIR"
    rm -f "$READY_FLAG"
    
    # Signal readiness on this node
    touch "$READY_FLAG"
    
    # Get list of hosts
    local hosts=$(yq -r '.hosts | .[]?' "$CONFIG_YAML")
    local total_hosts=$(echo "$hosts" | wc -l)
    total_hosts=$((total_hosts + 1))  # Include local node
    
    echo "Waiting for $total_hosts nodes to be ready..."
    
    # Check all remote nodes are ready
    local ready_count=1  # Local node is ready
    local elapsed=0
    
    while [ $ready_count -lt $total_hosts ] && [ $elapsed -lt $TIMEOUT ]; do
        ready_count=1  # Reset, counting local
        
        for host in $hosts; do
            if ssh -o ConnectTimeout=2 "$host" "[ -f $READY_FLAG ]" 2>/dev/null; then
                ready_count=$((ready_count + 1))
            fi
        done
        
        echo "Ready nodes: $ready_count/$total_hosts"
        
        if [ $ready_count -lt $total_hosts ]; then
            sleep 2
            elapsed=$((elapsed + 2))
        fi
    done
    
    if [ $ready_count -eq $total_hosts ]; then
        echo "All nodes ready, starting ETCD"
        return 0
    else
        echo "Timeout waiting for nodes, only $ready_count/$total_hosts ready"
        return 1
    fi
}

function cleanup_sync() {
    rm -f "$READY_FLAG"
}

case "$1" in
    start)
        if prepare_sync; then
            # Don't actually start etcd here, let systemd do it
            exit 0
        else
            exit 1
        fi
        ;;
    stop)
        cleanup_sync
        exit 0
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

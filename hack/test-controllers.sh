#!/usr/bin/env bash
# Run the controller suite as it needs to run: as root, in a throwaway network namespace, against
# dpservice on TAP devices with --enable-ipsec and a metalbond server. The encryption specs also run
# the metalnet binary and mlsbond's binaries, and restart dpservice through this script.
#
# Usage: hack/test-controllers.sh [ginkgo flags, e.g. -ginkgo.label-filter=encryption]
#
# Expects dpservice and mlsbond side by side with this repository, both built (DPSERVICE_DIR and
# MLSBOND_DIR override that). Everything except running the suite happens as the calling user, sudo
# is only asked for then.
set -Eeuo pipefail

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DPSERVICE_DIR=${DPSERVICE_DIR:-$BASE/../dpservice}
MLSBOND_DIR=${MLSBOND_DIR:-$DPSERVICE_DIR/docs/local/mlsbond}
NETNS=metalnet-test
SELF=$(realpath "$0")

# dpservice-start, dpservice-stop: called from the specs too, inside the namespace
tap_devices=(dtap0 dtap1 dtapvf_0 dtapvf_1 dtapvf_2 dtapvf_3)
dpservice_pid() { pgrep -f -- "--file-prefix=$NETNS" || true; }

dpservice_stop() {
	local pid

	pid=$(dpservice_pid)
	[ -n "$pid" ] || return 0
	kill -KILL "$pid"
	while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
}

dpservice_start() {
	(cd /tmp && exec env DP_CONF= setsid "$DPSERVICE_DIR/build/src/dpservice-bin" -l 0,1 --no-huge -m 4096 --file-prefix="$NETNS" --no-pci \
		--vdev=net_tap0,iface=dtap0,mac=22:22:22:22:22:00 --vdev=net_tap1,iface=dtap1,mac=22:22:22:22:22:01 \
		--vdev=net_tap2,iface=dtapvf_0,mac=66:66:66:66:66:00 --vdev=net_tap3,iface=dtapvf_1,mac=66:66:66:66:66:01 \
		--vdev=net_tap4,iface=dtapvf_2,mac=66:66:66:66:66:02 --vdev=net_tap5,iface=dtapvf_3,mac=66:66:66:66:66:03 \
		-- --pf0=dtap0 --pf1=dtap1 --vf-pattern=dtapvf_ --nic-type=tap --ipv6=fc00:1::1 --enable-ipv6-overlay \
		--grpc-port=1337 --no-stats --no-offload --enable-ipsec) > "$WORK/dpservice.log" 2>&1 < /dev/null &
	for _ in $(seq 100); do
		ip link show dtapvf_3 >/dev/null 2>&1 && ss -Hltn "sport = :1337" | grep -q . && break
		sleep 0.1
	done
	for dev in "${tap_devices[@]}"; do
		sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
		ip link set dev "$dev" up
	done
}

case "${1:-}" in
	dpservice-restart)
		dpservice_stop
		dpservice_start
		exit 0
		;;
	dpservice-stop)
		dpservice_stop
		exit 0
		;;
	dpservice-start)
		dpservice_start
		exit 0
		;;
	run-as-root)
		shift
		trap 'dpservice_stop; kill "$MB_PID" 2>/dev/null || true' EXIT
		ip link set lo up
		"$METALBOND_BIN" server --listen='[::1]:4711' > "$WORK/metalbond.log" 2>&1 &
		MB_PID=$!
		dpservice_start
		cd "$BASE/controllers"
		"$WORK/controllers.test" -test.timeout=30m -ginkgo.no-color "$@"
		exit
		;;
esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/metalnet-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
echo "work directory: $WORK"

make -C "$BASE" --no-print-directory envtest manifests
KUBEBUILDER_ASSETS=$("$BASE/bin/setup-envtest" use "$(sed -n 's/^ENVTEST_K8S_VERSION = //p' "$BASE/Makefile")" -p path)
(cd "$MLSBOND_DIR" && cargo build --quiet)
(cd "$BASE" && go test -c -o "$WORK/controllers.test" ./controllers && go build -ldflags "-X main.buildVersion=test" -o "$WORK/metalnet" . &&
	GOBIN="$WORK" go install "github.com/ironcore-dev/metalbond/cmd/metalbond@$(go list -m -f '{{.Version}}' github.com/ironcore-dev/metalbond)")

sudo ip netns del "$NETNS" 2>/dev/null || true
sudo ip netns add "$NETNS"
rc=0
sudo ip netns exec "$NETNS" env \
	WORK="$WORK" \
	DPSERVICE_DIR="$DPSERVICE_DIR" \
	KUBEBUILDER_ASSETS="$KUBEBUILDER_ASSETS" \
	METALNET_BIN="$WORK/metalnet" \
	METALBOND_BIN="$WORK/metalbond" \
	MLSBOND_BIN="$MLSBOND_DIR/target/debug" \
	DPSERVICE_RESTART_CMD="$SELF dpservice-restart" \
	DPSERVICE_STOP_CMD="$SELF dpservice-stop" \
	DPSERVICE_START_CMD="$SELF dpservice-start" \
	"$SELF" run-as-root "$@" || rc=$?
sudo ip netns del "$NETNS"
# what root left in there
sudo rm -rf "$WORK"
exit $rc

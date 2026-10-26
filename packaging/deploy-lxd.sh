#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LXD_HOST="${1:-169.254.1.3}"
INSTANCE="${2:-nfty}"
VOLUME_NAME="${INSTANCE}-data"
POOL_NAME="default"

echo "==> [1/4] Building latest nfty LXD image..."
./packaging/unikernel/build-unikernel.sh

echo "==> [2/4] Uploading image to LXD host ${LXD_HOST}..."
scp dist/lxd-container/lxd.tar.gz dist/lxd-container/rootfs.tar.gz "${LXD_HOST}:/tmp/"

echo "==> [3/4] Ensuring persistent LXD volume '${VOLUME_NAME}' is attached at /data and rolling image update..."
ssh -n "${LXD_HOST}" "
  set -e

  # 1. Create persistent storage volume if it doesn't exist yet
  if ! lxc storage volume show ${POOL_NAME} ${VOLUME_NAME} >/dev/null 2>&1; then
    echo '  -> Creating persistent LXD storage volume: ${POOL_NAME}/${VOLUME_NAME}'
    lxc storage volume create ${POOL_NAME} ${VOLUME_NAME} < /dev/null
  fi

  # 2. Import the new image under a staging alias
  lxc image delete nfty-ct-staging < /dev/null 2>/dev/null || true
  lxc image import /tmp/lxd.tar.gz /tmp/rootfs.tar.gz --alias nfty-ct-staging < /dev/null

  # 3. Check if instance already exists
  if lxc info ${INSTANCE} < /dev/null >/dev/null 2>&1; then
    # If the persistent volume isn't attached yet, migrate existing /data files into it first!
    if ! lxc config device show ${INSTANCE} < /dev/null | grep -q '^data:'; then
      echo '  -> Migrating existing /data files into persistent LXD volume ${VOLUME_NAME}...'
      rm -rf /tmp/nfty-data-backup && mkdir -p /tmp/nfty-data-backup
      lxc file pull -r ${INSTANCE}/data/. /tmp/nfty-data-backup/ < /dev/null 2>/dev/null || true
      lxc config device add ${INSTANCE} data disk pool=${POOL_NAME} source=${VOLUME_NAME} path=/data < /dev/null
      lxc file push -r /tmp/nfty-data-backup/. ${INSTANCE}/data/ < /dev/null 2>/dev/null || true
      rm -rf /tmp/nfty-data-backup
    fi

    echo '  -> Rebuilding ${INSTANCE} rootfs with new image (preserving /data volume & MAC/IP)...'
    lxc rebuild nfty-ct-staging ${INSTANCE} --force < /dev/null
  else
    echo '  -> Creating new instance ${INSTANCE} with persistent /data volume...'
    lxc init nfty-ct-staging ${INSTANCE} < /dev/null
    lxc config device add ${INSTANCE} data disk pool=${POOL_NAME} source=${VOLUME_NAME} path=/data < /dev/null
    lxc start ${INSTANCE} < /dev/null
  fi

  # 4. Promote staging image alias to nfty-ct
  FP=\$(lxc image info nfty-ct-staging | awk '/^Fingerprint:/ {print \$2}')
  lxc image alias delete nfty-ct < /dev/null 2>/dev/null || true
  lxc image alias create nfty-ct \"\$FP\" < /dev/null
  lxc image alias delete nfty-ct-staging < /dev/null 2>/dev/null || true

  sleep 3
  lxc list ${INSTANCE}
"

echo "==> [4/4] Rollout complete! Persistent /data (Nftyfile, auth.json, hosts.json) preserved."

#!/bin/bash
set -euo pipefail
RULE_SRC="${1:-/tmp/wavevm-udev-install/99-wavevm.rules}"
RULE_DST=/etc/udev/rules.d/99-wavevm.rules
TEST_USER="${WAVEVM_TEST_USER:-joeking}"

install -m 0644 "$RULE_SRC" "$RULE_DST"
# Ensure kvm group exists (Ubuntu provides it with qemu/kvm packages)
getent group kvm >/dev/null
usermod -aG kvm "$TEST_USER"
udevadm control --reload-rules
# Re-apply to live node if present (no rmmod needed)
if [[ -e /dev/wavevm ]]; then
  udevadm trigger --subsystem-match=misc --name-match=wavevm --action=add
  # Fallback if trigger does not retag a pre-existing misc node
  chgrp kvm /dev/wavevm
  chmod 0660 /dev/wavevm
fi
echo "INSTALLED $RULE_DST"
ls -la /dev/wavevm 2>/dev/null || echo "NOTE: /dev/wavevm absent (load module later; udev will apply)"
id "$TEST_USER"
getent group kvm

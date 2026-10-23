WaveVM /dev/wavevm persistent permissions (host install, 2026-10-23 Asia/Shanghai)

Installed on Ubuntu machine (not committed to git):
  /etc/udev/rules.d/99-wavevm.rules
  usermod -aG kvm joeking

Rule content (copy also in this directory as 99-wavevm.rules):
  KERNEL=="wavevm", SUBSYSTEM=="misc", GROUP="kvm", MODE="0660"

Why kvm group (not chmod 666):
  - Distro /dev/kvm uses GROUP=kvm MODE=0660 (lib/udev/rules.d/50-udev-default.rules).
  - Repo CI (scripts/ci_dual_node.sh) still does one-shot `sudo chmod 666 /dev/wavevm`
    after insmod; that works for morning §6 but does not survive reboot/re-insmod.
  - This host install is the durable fix. World-writable 0666 was NOT chosen.

Why NO modules-load.d / modprobe.d autoload:
  - wavevm.ko is out-of-tree (insmod from master_core/wavevm.ko); not installed under
    /lib/modules. Autoload would need a separate module install path.
  - CI Mode B/TCG paths explicitly require the module absent.
  - Manual `sudo insmod master_core/wavevm.ko` (or CI) remains the load path.
  - After any insmod, udev applies the rule automatically.

Verify now (no reboot required for the rule itself):
  ls -la /dev/wavevm          # expect: crw-rw---- 1 root kvm ...
  getent group kvm           # expect: joeking listed
  sg kvm -c 'test -r /dev/wavevm -a -w /dev/wavevm && echo OK'

After reboot:
  - Rule persists (file under /etc/udev/rules.d).
  - Group membership persists.
  - Module does NOT auto-load; run: sudo insmod /workspaces/WaveVM/master_core/wavevm.ko
  - Then: ls -la /dev/wavevm should already be root:kvm 0660 (no chmod needed).
  - Existing GUI/SSH sessions started before usermod need re-login or `newgrp kvm`
    for supplementary group kvm to appear in process credentials.

Reboot needed?: NO for installing the rule / fixing the live node.
              YES only if you want a fresh session with kvm in default groups
              without using `sg kvm` / `newgrp kvm`, or if you unload via reboot.

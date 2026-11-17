# Official WaveVM production build.
# Builds the typed entry only: wavevm_node_runtime and wvm_ctl.
# Independent master/slave CLIs are not official production targets
# and are no longer built (rollback: audit-evidence/legacy-cli-archive-20261117/).
.PHONY: all runtime ctl clean

all: runtime ctl

runtime:
	$(MAKE) -C node_runtime

ctl:
	$(MAKE) -C ctl_tool

clean:
	$(MAKE) -C node_runtime clean
	$(MAKE) -C ctl_tool clean

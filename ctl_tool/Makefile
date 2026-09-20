CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?= -pthread

TARGET = wvm_ctl
COMMON_DIR = ../common_include
SRCS = main.c admission_workspace.c capability_publication.c \
	runtime_profile_publication.c \
	$(COMMON_DIR)/wavevm_sha256.c \
	$(COMMON_DIR)/wavevm_canonical.c \
	$(COMMON_DIR)/wavevm_identity.c \
	$(COMMON_DIR)/wavevm_runtime_names.c \
	$(COMMON_DIR)/wavevm_manifest.c \
	$(COMMON_DIR)/wavevm_control.c \
	$(COMMON_DIR)/wavevm_capability.c \
	$(COMMON_DIR)/wavevm_runtime_profile.c \
	$(COMMON_DIR)/wavevm_lifecycle.c \
	$(COMMON_DIR)/wavevm_admission.c \
	$(COMMON_DIR)/wavevm_cluster.c \
	$(COMMON_DIR)/wavevm_reservation_runtime.c \
	$(COMMON_DIR)/wavevm_fault_engine.c \
	$(COMMON_DIR)/wavevm_coordinator.c \
	$(COMMON_DIR)/wavevm_admission_evidence.c \
	$(COMMON_DIR)/wavevm_admission_provider.c \
	$(COMMON_DIR)/wavevm_admission_authority_owner.c \
	$(COMMON_DIR)/wavevm_admission_stage.c \
	$(COMMON_DIR)/wavevm_admission_transport.c \
	$(COMMON_DIR)/wavevm_admission_route.c \
	$(COMMON_DIR)/wavevm_membership_coordinator.c \
	$(COMMON_DIR)/wavevm_admission_orchestrator.c \
	$(COMMON_DIR)/wavevm_control_plane.c \
	$(COMMON_DIR)/wavevm_envelope.c \
	$(COMMON_DIR)/wavevm_membership_controller.c \
	$(COMMON_DIR)/wavevm_membership_control.c \
	$(COMMON_DIR)/wavevm_control_transport.c \
	$(COMMON_DIR)/wavevm_control_owner.c \
	$(COMMON_DIR)/wavevm_control_service.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) $(SRCS) $(LDFLAGS) -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean

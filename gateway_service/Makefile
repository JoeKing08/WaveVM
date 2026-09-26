CC = gcc
# 必须包含 -pthread 因为 aggregator.c 用到了多线程
CFLAGS = -Wall -O2 -I../common_include -pthread
TARGET = wavevm_gateway
SRCS = aggregator.c main.c \
	../common_include/wavevm_sha256.c \
	../common_include/wavevm_canonical.c \
	../common_include/wavevm_identity.c \
	../common_include/wavevm_runtime_names.c \
	../common_include/wavevm_manifest.c \
	../common_include/wavevm_lifecycle.c \
	../common_include/wavevm_membership.c \
	../common_include/wavevm_capability.c \
	../common_include/wavevm_admission.c \
	../common_include/wavevm_cluster.c \
	../common_include/wavevm_reservation_runtime.c \
	../common_include/wavevm_fault_engine.c \
	../common_include/wavevm_coordinator.c \
	../common_include/wavevm_control_plane.c \
	../common_include/wavevm_membership_controller.c \
	../common_include/wavevm_membership_control.c \
	../common_include/wavevm_control.c \
	../common_include/wavevm_control_transport.c \
	../common_include/wavevm_control_owner.c \
	../common_include/wavevm_control_client.c \
	../common_include/wavevm_tls_control_connector.c \
	../common_include/wavevm_runtime_gate.c \
	../common_include/wavevm_envelope.c \
	../common_include/wavevm_route_runtime.c \
	../common_include/wavevm_route_control.c \
	../common_include/wavevm_route_delivery.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

clean:
	rm -f $(TARGET)

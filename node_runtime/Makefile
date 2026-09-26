CC ?= gcc
CFLAGS ?= -Wall -O2 -msse4.2 -std=gnu11 -D_POSIX_C_SOURCE=200809L
CPPFLAGS ?= -I../common_include -pthread
LDFLAGS ?= -pthread

TARGET = ../wavevm_node_runtime

MASTER_OBJS = master_logic.o master_user.o master_main.o
SLAVE_OBJS = slave_hybrid.o slave_vfio.o
COMMON_OBJS = resources.o sha256.o canonical.o identity.o runtime_names.o manifest.o lifecycle.o runtime_gate.o runtime_dispatch.o executor_abi.o executor_session.o envelope.o memory.o vcpu_handoff.o vcpu_handoff_cache.o x86_context.o local_memory.o route_runtime.o executor_bridge.o vcpu_coordinator.o vcpu_service.o memory_service.o ingress.o directory_store.o kvm_page_cache.o control.o route_delivery.o runtime_delivery.o membership_control.o membership_controller.o reservation_runtime.o admission_stage.o admission_receiver.o route_control.o control_transport.o control_owner.o tls_control_connector.o admission_node_service.o admission_slot_registry.o admission_runtime_agent.o

all: $(TARGET)

$(TARGET): main.o admission_main.o $(MASTER_OBJS) $(SLAVE_OBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

main.o: main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_main.o: admission_main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

master_logic.o: ../master_core/logic_core.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

master_user.o: ../master_core/user_backend.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

master_main.o: ../master_core/main_wrapper.c runtime_context.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

slave_hybrid.o: ../slave_daemon/slave_hybrid.c runtime_context.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

slave_vfio.o: ../slave_daemon/slave_vfio.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

resources.o: ../common_include/wavevm_resources.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

sha256.o: ../common_include/wavevm_sha256.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

canonical.o: ../common_include/wavevm_canonical.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

identity.o: ../common_include/wavevm_identity.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

runtime_names.o: ../common_include/wavevm_runtime_names.c ../common_include/wavevm_lifecycle.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

manifest.o: ../common_include/wavevm_manifest.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

lifecycle.o: ../common_include/wavevm_lifecycle.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

runtime_gate.o: ../common_include/wavevm_runtime_gate.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

runtime_dispatch.o: ../common_include/wavevm_runtime_dispatch.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

executor_abi.o: ../common_include/wavevm_executor_abi.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

executor_session.o: ../common_include/wavevm_executor_session.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

envelope.o: ../common_include/wavevm_envelope.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

memory.o: ../common_include/wavevm_memory.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

vcpu_handoff.o: ../common_include/wavevm_vcpu_handoff.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

vcpu_handoff_cache.o: ../common_include/wavevm_vcpu_handoff_cache.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

x86_context.o: ../common_include/wavevm_x86_context.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

local_memory.o: ../common_include/wavevm_local_memory.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

route_runtime.o: ../common_include/wavevm_route_runtime.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

executor_bridge.o: executor_bridge.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

vcpu_coordinator.o: vcpu_coordinator.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

vcpu_service.o: vcpu_service.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

memory_service.o: memory_service.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

ingress.o: ingress.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

directory_store.o: directory_store.c directory_store.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

kvm_page_cache.o: kvm_page_cache.c kvm_page_cache.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

control.o: ../common_include/wavevm_control.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

route_delivery.o: ../common_include/wavevm_route_delivery.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

runtime_delivery.o: ../common_include/wavevm_runtime_delivery.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

membership_control.o: ../common_include/wavevm_membership_control.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

membership_controller.o: ../common_include/wavevm_membership_controller.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

reservation_runtime.o: ../common_include/wavevm_reservation_runtime.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_stage.o: ../common_include/wavevm_admission_stage.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_receiver.o: ../common_include/wavevm_admission_receiver.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

route_control.o: ../common_include/wavevm_route_control.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

control_transport.o: ../common_include/wavevm_control_transport.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

control_owner.o: ../common_include/wavevm_control_owner.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

tls_control_connector.o: ../common_include/wavevm_tls_control_connector.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_node_service.o: ../common_include/wavevm_admission_node_service.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_slot_registry.o: ../common_include/wavevm_admission_slot_registry.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

admission_runtime_agent.o: ../common_include/wavevm_admission_runtime_agent.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) main.o $(MASTER_OBJS) $(SLAVE_OBJS) $(COMMON_OBJS)

.PHONY: all clean

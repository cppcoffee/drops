all: xdp_drops.o

.PHONY: xdp_drops.o
xdp_drops.o: xdp_drops.c
	clang -Wall -Wextra \
		-O2 -emit-llvm \
		-c xdp_drops.c -S -o - \
	| llc -march=bpf -filetype=obj -o $@

verb:
	ip link set dev p4p1 xdp obj ./xdp_drops.o verb

.PHONY:
clean:
	rm xdp_drops.o

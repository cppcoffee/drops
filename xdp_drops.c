#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/tcp.h>
#include <linux/version.h>

#include <stddef.h>
#include <stdint.h>

#include "bpf_helper.h"
#include "ipv6_helper.h"


#define TCP_PROTO 0x06
#define TIMEPRIOD_SIZE 8
#define TIMEPRIOD_MASK 0x7
#define RX_SYN_LIMIT (TIMEPRIOD_SIZE * 6000)

#define VERDICT_ROUND_VALUE 10

#define htonl(x) __constant_htonl(x)
#define ntohl(x) __constant_ntohl(x)
#define htons(x) __constant_htons(x)
#define ntohs(x) __constant_ntohs(x)


#define DEBUG 0
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe (remember use cat)
 */
#define bpf_debug(fmt, ...)                                                    \
    ({                                                                         \
        char ____fmt[] = fmt;                                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#else
//# define bpf_debug(fmt, ...) { } while (0)
#define bpf_debug(fmt, ...)
#endif


struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};


struct cookie_s {
    int active; // drop tcp-syn package.
    uint32_t time;

    uint64_t rvalue;
    uint64_t count;
    uint64_t syn_cnt[TIMEPRIOD_SIZE];
};
typedef struct cookie_s cookie_t;


struct bpf_map_def SEC("maps") rx_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(cookie_t),
    .max_entries = 1,
};


static void sc_update_active(cookie_t *cookie)
{
    int i, pos;
    uint64_t now, diff;
    uint64_t total;

    now = bpf_ktime_get_ns();
    now = now >> 32; // second

    ++cookie->count;

    diff = now - cookie->time;

    if (diff < 1) {
        return; // time is not yet
    }

    pos = now & TIMEPRIOD_MASK;

    cookie->syn_cnt[pos] = cookie->count;
    cookie->count = 0;
    cookie->time = now;

    if (pos == 0) {
        total = 0;

        for (i = 0; i < TIMEPRIOD_SIZE; i++) {
            total += cookie->syn_cnt[i];
        }

        if (total >= RX_SYN_LIMIT) {
            cookie->active = 1;
        } else {
            cookie->active = 0;
        }
    }
}


static int sc_action_verdict(cookie_t *cookie)
{
    if (cookie->active == 0) {
        return XDP_PASS;
    }

    /* Use simple counter */
    if ((cookie->rvalue + 1) >= (VERDICT_ROUND_VALUE * 3)) {
        cookie->rvalue = 0; /* Reset counter */
    } else {
        ++cookie->rvalue;
    }

    if (cookie->rvalue < VERDICT_ROUND_VALUE) {
        return XDP_PASS;

    } else if (cookie->rvalue >= VERDICT_ROUND_VALUE &&
               cookie->rvalue < (VERDICT_ROUND_VALUE * 3)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}


static int handle_ipv4(void *data, uint64_t nh_off, void *data_end)
{
    int cpu;
    cookie_t *cookie;
    struct tcphdr *th;
    struct iphdr *iph = data + nh_off;

    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == TCP_PROTO) {
        th = (void *)iph + (iph->ihl * 4);

        if ((void *)th + sizeof(*th) > data_end) {
            return XDP_PASS;
        }

        if (th->syn) {
            cpu = bpf_get_smp_processor_id();
            cookie = bpf_map_lookup_elem(&rx_map, &cpu);

            if (!cookie) {
                return XDP_PASS;
            }

            sc_update_active(cookie);
            return sc_action_verdict(cookie);
        }
    }

    return XDP_PASS;
}


static int ipv6_playload_offset(struct ipv6hdr *ip6h, void *data_end)
{
    int i;
    uint64_t hdrlen;
    uint8_t nexthdr = ip6h->nexthdr;
	int off = sizeof(struct ipv6hdr);
    void *start = ip6h;

    if (start + off > data_end) {
        return -1;
    }

    for (i = 0; i < 10; i++) {
        if (!ipv6_ext_hdr(nexthdr)) {
            break;
        }

        if (nexthdr == NEXTHDR_NONE) {
            return -1;
        }

        struct ipv6_opt_hdr *hp = start + off;
        if ((void *)hp + sizeof(*hp) > data_end) {
            return -1;
        }

        if (nexthdr == NEXTHDR_FRAGMENT) {
            hdrlen = sizeof(struct frag_hdr);
        } else if (nexthdr == NEXTHDR_AUTH) {
            hdrlen = ipv6_authlen(hp);
        } else {
            hdrlen = ipv6_optlen(hp);
        }

        off += hdrlen;
        nexthdr = hp->nexthdr;
    }

    if (start + off > data_end) {
        return -1;
    }

    return off;
}


static int handle_ipv6(void *data, uint64_t nh_off, void *data_end)
{
    int cpu, off;
    cookie_t *cookie;
    struct tcphdr *th;
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void *)ip6h + sizeof(*ip6h) + sizeof(*th) > data_end) {
        return XDP_PASS;
    }

    off = ipv6_playload_offset(ip6h, data_end);
    if (off == -1) {
        return XDP_PASS;
    }

    th = (void *)ip6h + off;
    if ((void *)th + sizeof(*th) > data_end) {
        return XDP_PASS;
    }

    if (th->syn) {
        cpu = bpf_get_smp_processor_id();
        cookie = bpf_map_lookup_elem(&rx_map, &cpu);

        if (!cookie) {
            return XDP_PASS;
        }

        sc_update_active(cookie);
        return sc_action_verdict(cookie);
    }

    return XDP_PASS;
}


SEC("prog")
int xdp_droplet_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    uint64_t nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    uint16_t h_proto = eth->h_proto;
    int i;

    /* Handle double VLAN tagged packet. See
     * https://en.wikipedia.org/wiki/IEEE_802.1ad */
    for (i = 0; i < 2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end) {
                return XDP_PASS;
            }
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IP)) {
        return handle_ipv4(data, nh_off, data_end);
    } else if (h_proto == htons(ETH_P_IPV6)) {
        return handle_ipv6(data, nh_off, data_end);
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

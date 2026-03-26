/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>

#include "xsk_def_xdp_prog.h"

#define DEFAULT_QUEUE_IDS 64

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

/* Program refcount, in order to work properly,
 * must be declared before any other global variables
 * and initialized with '1'.
 */
volatile int refcnt = 1;

/* This is the program for post 5.3 kernels. */
SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
	/* Make sure refcount is referenced by the program */
	if (!refcnt)
		return XDP_PASS;

	void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->saddr == bpf_htonl(0x0A0A02CC)){
        bpf_printk("Redirecting packet to xsk\n");
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    }

	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	// return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);

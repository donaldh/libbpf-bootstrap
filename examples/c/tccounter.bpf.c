// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "tccounter.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32);
	__type(key, struct key);
	__type(value, struct value);
} packet_stats SEC(".maps");


static inline void count_by_srcip(__u32 srcip, int bytes)
{
	struct key key = {
		.srcip = srcip
	};
	struct value *value = bpf_map_lookup_elem(&packet_stats, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	} else {
		struct value newval = { 1, bytes };
		bpf_map_update_elem(&packet_stats, &key, &newval, BPF_NOEXIST);
	}
}

SEC("tc")
int count_packets(struct __sk_buff *skb)
{
	count_by_srcip(0, skb->data_end - skb->data);

	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

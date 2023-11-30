/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdbool.h>
//XXhash
#include "../../vcpkg/installed/x64-linux/include/xxh3.h"
// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"



#include "common_kern_user.h" /* defines: struct datarec; */

#define __bpf_printk(fmt, ...)					\
({												\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);					\
})

/*
 * __bpf_vprintk wraps the bpf_trace_vprintk helper with variadic arguments
 * instead of an array of u64.
 */
#define __bpf_vprintk(fmt, args...)						\
({														\
	static const char ___fmt[] = fmt;					\
	unsigned long long ___param[___bpf_narg(args)];		\
														\
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	\
	___bpf_fill(___param, args);						\
	_Pragma("GCC diagnostic pop")						\
														\
	bpf_trace_vprintk(___fmt, sizeof(___fmt),			\
			  ___param, sizeof(___param));				\
})

/* Use __bpf_printk when bpf_printk call has 3 or fewer fmt args
 * Otherwise use __bpf_vprintk
 */
#define ___bpf_pick_printk(...) \
	___bpf_nth(_, ##__VA_ARGS__, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,	\
		   __bpf_vprintk, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,		\
		   __bpf_vprintk, __bpf_vprintk, __bpf_printk /*3*/, __bpf_printk /*2*/,\
		   __bpf_printk /*1*/, __bpf_printk /*0*/)

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct Cms);
	__uint(max_entries, 1);
} cms_map SEC(".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	bpf_printk("arrivato pacchetto");
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = 0; /* XDP_PASS = 2 */

	// __u64 bytes = data_end - data; /* Calculate packet length */


	// //parsing pacchetto
	__u32 ip_src =0;
	__u32 ip_dst =0;
	__u32 proto =0;
	__u32 src_port =0;
	__u32 dst_port =0;
	

	struct ethhdr *eth;
	struct hdr_cursor nh1;
	struct hdr_cursor nh2;
	struct hdr_cursor nh3;
	struct hdr_cursor nh4;
	int nh_type;
	nh1.pos = data;
	nh2.pos = data;
	nh3.pos = data;
	nh4.pos = data;
	//easier to copy than to modify parse hdr functions
	nh_type = parse_ethhdr(&nh1, data_end, &eth); //"../common/parsing_helpers.h"
	nh_type = parse_ethhdr(&nh2, data_end, &eth); //"../common/parsing_helpers.h"
	nh_type = parse_ethhdr(&nh3, data_end, &eth); //"../common/parsing_helpers.h"
	nh_type = parse_ethhdr(&nh4, data_end, &eth); //"../common/parsing_helpers.h"
	
	if(nh_type == bpf_htons(ETH_P_IP)){ //ip =8
		// bpf_printk("prova %d",nh_type);
		struct iphdr *iph;
		proto =  parse_iphdr(&nh1, data_end, &iph);
		ip_src = parse_iphdr_saddr(&nh2, data_end, &iph);
		ip_dst = parse_iphdr_daddr(&nh3, data_end, &iph);
		// if(proto == IPPROTO_TCP && ip_src!=ip_dst){
		if(proto == IPPROTO_TCP){
			// bpf_printk("iphdr %u,%u,%d",ip_src,ip_dst,proto);
			struct tcphdr *tcph;
			src_port = parse_tcphdr_source(&nh1, data_end, &tcph);
			dst_port = parse_tcphdr_dest(&nh2, data_end, &tcph);
			// bpf_printk("tcpHDR %u,%u",src_port,dst_port);

			__u32 buffer[5] = {ip_src, ip_dst, proto, src_port, dst_port};

			__u32 hash = XXH32(buffer, sizeof(buffer), 42);
			__u32 index = hash%CMS_SIZE;

			bpf_printk("Hash =%u Index=%u",hash,index);

			// __u32 hash1 = XXH32(&hash, sizeof(hash), 42);
			// __u32 index1 = hash1%CMS_SIZE;

			// __u32 hash2 = XXH32(&hash1, sizeof(hash1), 42);
			// __u32 index2 = hash2%CMS_SIZE;

			// __u32 hash3 = XXH32(&hash2, sizeof(hash2), 42);
			// __u32 index3 = hash3%CMS_SIZE;
			// parte cms
			struct Cms *cms;
			cms = bpf_map_lookup_elem(&cms_map, &key);

			if (!cms)
				return XDP_ABORTED;
			lock_xadd(&cms->cms[0][index], 1);
			// lock_xadd(&cms->cms[1][index1], 1);
			// lock_xadd(&cms->cms[2][index2], 1);
			// lock_xadd(&cms->cms[3][index3], 1);
			

			//hash non puo essere usata nei loop
			// for (int i=1; i<CMS_ROWS;i++){
			// 	hash = XXH32(&hash, sizeof(hash), 42);
			// 	bpf_printk("Hash %d =%u",i,hash);
			// }

		};
	};





	// XXH32_hash_t hash = XXH32





	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
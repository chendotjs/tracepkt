#include <bcc/proto.h>
#include <linux/netfilter/x_tables.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>

#define FUNNAMESIZ 30

// Event structure
struct ipt_event_t {
  /* Iptables trace */
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u64 hook;
  u64 verdict;
  u64 netns;
  char tablename[XT_TABLE_MAXNAMELEN];
  char funcname[FUNNAMESIZ];
};

BPF_PERF_OUTPUT(ipt_events);

#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif

// Arg stash structure
struct ipt_do_table_args {
  struct sk_buff *skb;
  const struct nf_hook_state *state;
  struct xt_table *table;
};

BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);

#define member_address(source_struct, source_member)                           \
  ({                                                                           \
    void *__ret;                                                               \
    __ret = (void *)(((char *)source_struct) +                                 \
                     offsetof(typeof(*source_struct), source_member));         \
    __ret;                                                                     \
  })
#define member_read(destination, source_struct, source_member)                 \
  do {                                                                         \
    bpf_probe_read(destination, sizeof(source_struct->source_member),          \
                   member_address(source_struct, source_member));              \
  } while (0)

/**
 * Common tracepoint handler. Detect IPv4/IPv6 ICMP echo request and replies and
 * emit event with address, interface and namespace.
 */
static inline int do_trace_skb(struct ipt_event_t *evt, void *ctx,
                               struct sk_buff *skb) {
  char *skb_head;
  u16 transport_header;
  u16 network_header;
  struct iphdr iphdr;
  struct tcphdr tcphdr;
  u16 sport = 0, dport = 0;
  struct net_device *dev;
  struct net *net;
  struct ns_common ns_common;

  member_read(&skb_head, skb, head); // skb_head = skb->head;

  member_read(&network_header, skb, network_header);
  member_read(&transport_header, skb, transport_header);

  // Compute IP/TCP Header address
  char *iphdr_address = skb_head + network_header;
  char *tcphdr_address = skb_head + transport_header;

  bpf_probe_read(&iphdr, sizeof(iphdr), iphdr_address);
  bpf_probe_read(&tcphdr, sizeof(tcphdr), tcphdr_address);

  if (iphdr.protocol != IPPROTO_UDP) {
    return -1;
  }

  evt->saddr = iphdr.saddr;
  evt->daddr = iphdr.daddr;

  sport = tcphdr.source;
  dport = tcphdr.dest;
  evt->sport = ntohs(sport);
  evt->dport = ntohs(dport);

  // Get device pointer, we'll need it to get the name and network namespace
  member_read(&dev, skb, dev);

  // Get netns id. The code below is equivalent to: evt->netns =
  // dev->nd_net.net->ns.inum
  possible_net_t *pnd_net = &(dev->nd_net);
  member_read(&net, pnd_net, net);
  member_read(&ns_common, net, ns);
  evt->netns = ns_common.inum;

  return 0;
}

/**
 * Common iptables functions
 */

static inline int __ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
                                    const struct nf_hook_state *state,
                                    struct xt_table *table) {
  u32 pid = bpf_get_current_pid_tgid();

  // stash the arguments for use in retprobe
  struct ipt_do_table_args args = {
      .skb = skb,
      .state = state,
      .table = table,
  };
  cur_ipt_do_table_args.update(&pid, &args);
  return 0;
};

static inline int __ipt_do_table_out(struct pt_regs *ctx) {
  // Load arguments
  u32 pid = bpf_get_current_pid_tgid();

  struct ipt_do_table_args *args;
  args = cur_ipt_do_table_args.lookup(&pid);
  if (args == NULL) {
    return 0; // missed entry
  }
  cur_ipt_do_table_args.delete(&pid);

  // Prepare event for userland
  struct ipt_event_t evt = {};

  // Save kprobe func name
  strcpy(evt.funcname, "ipt_do_table");

  // Load packet information
  struct sk_buff *skb = args->skb;
  int err = do_trace_skb(&evt, ctx, skb);
  if (err != 0) {
    return 0;
  }

  // Store the hook
  const struct nf_hook_state *state = args->state;
  member_read(&evt.hook, state, hook);

  // Store the table name
  struct xt_table *table = args->table;
  member_read(&evt.tablename, table, name);

  // Store the verdict
  int ret = PT_REGS_RC(ctx);
  evt.verdict = ret;

  // Send event
  ipt_events.perf_submit(ctx, &evt, sizeof(evt));

  return 0;
}

/**
 * Attach to Kernel iptables main function
 */

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb,
                         const struct nf_hook_state *state,
                         struct xt_table *table) {
  return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ipt_do_table(struct pt_regs *ctx) {
  return __ipt_do_table_out(ctx);
}

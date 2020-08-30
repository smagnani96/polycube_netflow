/*Protocol types according to the standard*/
#define ETH_P_IP        0x0800 
#define ETH_P_IPV6      0x86DD
#define IPPROTO_ICMP    1
#define IPPROTO_ICMPV6  58
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

#define FLOW_MAP_SIZE   100

enum CONNECTION_STATE {
    UP, SENT_CLOSE_FROM_ME, SENT_CLOSE_FROM_PARTNER, CLOSED
};

/*Ethernet Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h (slightly different)*/
struct eth_hdr {
    __be64 dst: 48;
    __be64 src: 48;
    __be16 proto;
} __attribute__((packed));

/*IPv4 Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
} __attribute__((packed));

/*IPv6 Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/ipv6.h*/
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8      tc1:4,
        version:4;
  __u8      flow_lbl1:4,
        tc2:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8      version:4,
        tc1:4;
  __u8      tc2:4,
        flow_lbl1:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
  __u8      flow_lbl2[2];

  __be16      payload_len;
  __u8      nexthdr;
  __u8      hop_limit;

  __u64    saddr[2];
  __u64    daddr[2];
};

/*TCP Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

/*UDP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/udp.h */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

/*ICMP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h*/
struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((packed));

/*Features to be exported*/
struct features {
    //Real features
    uint64_t packets;                    // Number of packets
    uint64_t bytes;                      // Number of bytes
    uint64_t flows;                      // Number of flows (if FYN then restarted)
    uint8_t flags;                       // Flags if any
    uint8_t  tos;                        // ToS value
    uint64_t start_timestamp;            // Connection begin timestamp
    uint64_t alive_timestamp;            // Last message received timestamp
    uint8_t status;                      // To track reset & reuse
} __attribute__((packed));

/*Flow identifier IPv4*/
struct flow_identifier_v4 {
    __be32 saddr;                        //IP source address
    __be32 daddr;                        //IP dest address
    __be16 sport;                        //Source port
    __be16 dport;                        //Dest port
    __u8   proto;                        //Protocol ID
} __attribute__((packed));

/*Flow identifier IPv6*/
struct flow_identifier_v6 {
    __u64  saddr[2];                     //IP source address
    __u64  daddr[2];                     //IP dest address
    __be16 sport;                        //Source port
    __be16 dport;                        //Dest port
    __u8   proto;                        //Protocol ID
} __attribute__((packed));


/*Flow map IPv4*/
BPF_TABLE("extern", struct flow_identifier_v4, struct features, FLOW_MAP_V4, FLOW_MAP_SIZE);

/*Flow map IPv6*/
BPF_TABLE("extern", struct flow_identifier_v6, struct features, FLOW_MAP_V6, FLOW_MAP_SIZE);

static __always_inline void push_ipv4(struct flow_identifier_v4 *key, uint16_t len, uint8_t tos) {
  uint64_t curr_time = pcn_get_time_epoch();
  struct features *value = FLOW_MAP_V4.lookup(key);
  if(!value) {
    struct features new = {.packets=1, .bytes=len, .flows=1, .tos=tos, .start_timestamp=curr_time, .alive_timestamp=curr_time, .status=0, .flags=0};
    FLOW_MAP_V4.insert(key, &new);
  } else {
    value->packets++;
    value->bytes += len;
    value->alive_timestamp = curr_time;
  }
}

static __always_inline void push_ipv6(struct flow_identifier_v6 *key, uint16_t len, uint8_t tos) {
  uint64_t curr_time = pcn_get_time_epoch();
  struct features *value = FLOW_MAP_V6.lookup(key);
  if(!value) {
    struct features new = {.packets=1, .bytes=len, .flows=1, .tos=tos, .start_timestamp=curr_time, .alive_timestamp=curr_time, .status=0, .flags=0};
    FLOW_MAP_V6.insert(key, &new);
  } else {
    value->packets++;
    value->bytes += len;
    value->alive_timestamp = curr_time;
  }
}

static __always_inline void push_tcp_ipv4(struct tcphdr *tcp, struct flow_identifier_v4 *key, uint16_t len, uint8_t tos) {
  uint64_t curr_time = pcn_get_time_epoch();
  struct features *value = FLOW_MAP_V4.lookup(key);
  if(!value) {
    struct features new = {.packets=1, .bytes=len, .flows=1, .tos=tos, .start_timestamp=curr_time, .alive_timestamp=curr_time, .flags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin, .status=0};
    FLOW_MAP_V4.insert(key, &new);
  } else {
    value->packets++;
    value->bytes += len;
    value->alive_timestamp = curr_time;
    value->flags |= (tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4) | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
    /*EGRESS*/
    if(tcp->syn && value->status == CLOSED) {
        value->flows++;
        value->status = UP;
    } else if(tcp->fin) {
      if(value->status==SENT_CLOSE_FROM_PARTNER)
        value->status = CLOSED;
      else
        value->status = SENT_CLOSE_FROM_ME;
    } else if(tcp->rst) {
      value->status = CLOSED;
    }
  }
}

static __always_inline void push_tcp_ipv6(struct tcphdr *tcp, struct flow_identifier_v6 *key, uint16_t len, uint8_t tos) {
  uint64_t curr_time = pcn_get_time_epoch();
  struct features *value = FLOW_MAP_V6.lookup(key);
  if(!value) {
    struct features new = {.packets=1, .bytes=len, .flows=1, .tos=tos, .start_timestamp=curr_time, .alive_timestamp=curr_time, .flags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin, .status=0};
    FLOW_MAP_V6.insert(key, &new);
  } else {
    value->packets++;
    value->bytes += len;
    value->alive_timestamp = curr_time;
    value->flags |= (tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4) | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
    /*INGRESS*/
    if(tcp->syn && value->status == CLOSED) {
        value->flows++;
        value->status = UP;
    } else if(tcp->fin) {
      if(value->status==SENT_CLOSE_FROM_PARTNER)
        value->status = CLOSED;
      else
        value->status = SENT_CLOSE_FROM_ME;
    } else if(tcp->rst) {
      value->status = CLOSED;
    }
  }
}

static __always_inline int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  /*Parsing L2*/
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return RX_OK;

  if (ethernet->proto == bpf_htons(ETH_P_IP)) {
    /*Parsing L3*/
    struct iphdr *ip = data + sizeof(struct eth_hdr);
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
      return RX_OK;
    
    if ((int) ip->version != 4)
      return RX_OK;
    
    uint8_t ip_header_len = ip->ihl << 2;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
      //Parsing L4 TCP
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end)
        return RX_OK;

      struct flow_identifier_v4 key = {.saddr=ip->daddr, .daddr=ip->saddr, .sport=tcp->dest, .dport=tcp->source, .proto=ip->protocol};
      push_tcp_ipv4(tcp, &key, bpf_ntohs(ip->tot_len), ip->tos);
      break;
    }
    case IPPROTO_UDP: {
      //Parsing L4 UDP
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return RX_OK;
      }
      
      struct flow_identifier_v4 key = {.saddr=ip->daddr, .daddr=ip->saddr,.sport=udp->dest, .dport=udp->source, .proto=ip->protocol};
      push_ipv4(&key, bpf_ntohs(ip->tot_len), ip->tos);
      break;
    }
    case IPPROTO_ICMP: {
      /*Parsing L4 ICMP*/
      struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) icmp + sizeof(*icmp) > data_end) {
        return RX_OK;
      }

      struct flow_identifier_v4 key = {.saddr=ip->daddr, .daddr=ip->saddr, .sport=0, .dport=0, .proto=ip->protocol};
      push_ipv4(&key, bpf_ntohs(ip->tot_len), ip->tos);
      break;
    }
    /*Ignored protocol*/
    default : {
      pcn_log(ctx, LOG_DEBUG, "IPv4 Untreated protocol");
      break;
    }
    }
  } else if (ethernet->proto == bpf_htons(ETH_P_IPV6)) {
    /*IPv6*/
    struct ipv6hdr *ip = data + sizeof(struct eth_hdr);
    
    if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
      return RX_OK;
    
    if ((int) ip->version != 6)
      return RX_OK;
    
    switch(ip->nexthdr) {
      case IPPROTO_TCP : {
        //Parsing L4 TCP
        struct tcphdr *tcp = data + sizeof(struct eth_hdr) + sizeof(struct ipv6hdr);
        if ((void *) tcp + sizeof(*tcp) > data_end)
          return RX_OK;

        struct flow_identifier_v6 key = {.sport=tcp->dest, .dport=tcp->source, .proto=ip->nexthdr};
        key.saddr[0] = ip->daddr[0]; key.saddr[1] = ip->daddr[1];
        key.daddr[0] = ip->saddr[0]; key.daddr[1] = ip->saddr[1];
        push_tcp_ipv6(tcp, &key, bpf_ntohs(ip->payload_len), (ip->tc1 << 4) | (ip->tc2));
        break;
      }
      case IPPROTO_UDP : {
        //Parsing L4 UDP
        struct udphdr *udp = data + sizeof(struct eth_hdr) + sizeof(struct ipv6hdr);
        if ((void *) udp + sizeof(*udp) > data_end) {
          return RX_OK;
        }
        
        struct flow_identifier_v6 key = {.sport=udp->dest, .dport=udp->source, .proto=ip->nexthdr};
        key.saddr[0] = ip->daddr[0]; key.saddr[1] = ip->daddr[1];
        key.daddr[0] = ip->saddr[0]; key.daddr[1] = ip->saddr[1];
        push_ipv6(&key, bpf_ntohs(ip->payload_len), (ip->tc1 << 4) | (ip->tc2));
        break;
      }
      case IPPROTO_ICMPV6 : {
        /*Parsing L4 ICMP*/
        struct icmphdr *icmp = data + sizeof(struct eth_hdr) + sizeof(struct ipv6hdr);
        if ((void *) icmp + sizeof(*icmp) > data_end) {
          return RX_OK;
        }

        struct flow_identifier_v6 key = {.sport=0, .dport=0, .proto=ip->nexthdr};
        key.saddr[0] = ip->daddr[0]; key.saddr[1] = ip->daddr[1];
        key.daddr[0] = ip->saddr[0]; key.daddr[1] = ip->saddr[1];
        push_ipv6(&key, bpf_ntohs(ip->payload_len), (ip->tc1 << 4) | (ip->tc2));
        break;
      }
      default: {
        pcn_log(ctx, LOG_DEBUG, "IPv6 Untreated protocol");
        break;
      }
    }
  } else {
    pcn_log(ctx, LOG_DEBUG, "Not an IP Protocol");
  }

  /* Here operations after the capture */
  return RX_OK;
}
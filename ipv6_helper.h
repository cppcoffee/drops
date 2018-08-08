#ifndef _IPV6_H_
#define _IPV6_H_

#include <linux/types.h>


/*
 *	NextHeader field of IPv6 header
 */
#define NEXTHDR_HOP     0   /* Hop-by-hop option header. */
#define NEXTHDR_TCP     6   /* TCP segment. */
#define NEXTHDR_UDP     17	/* UDP message. */
#define NEXTHDR_IPV6        41  /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING     43  /* Routing header. */
#define NEXTHDR_FRAGMENT    44  /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE         47  /* GRE header. */
#define NEXTHDR_ESP         50  /* Encapsulating security payload. */
#define NEXTHDR_AUTH        51  /* Authentication header. */
#define NEXTHDR_ICMP        58  /* ICMP for IPv6. */
#define NEXTHDR_NONE        59  /* No next header */
#define NEXTHDR_DEST        60  /* Destination options header. */
#define NEXTHDR_SCTP        132 /* SCTP message. */
#define NEXTHDR_MOBILITY    135 /* Mobility header. */

#define NEXTHDR_MAX		255


#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)


/*
 *	fragmentation header
 */
struct frag_hdr {
	__u8	nexthdr;
	__u8	reserved;
	__be16	frag_off;
	__be32	identification;
};


inline int ipv6_ext_hdr(uint8_t nexthdr)
{
    /*
     * find out if nexthdr is an extension header or a protocol
     */
    return ((nexthdr == NEXTHDR_HOP) ||
        (nexthdr == NEXTHDR_ROUTING) ||
        (nexthdr == NEXTHDR_FRAGMENT) ||
        (nexthdr == NEXTHDR_AUTH) ||
        (nexthdr == NEXTHDR_NONE) ||
        (nexthdr == NEXTHDR_DEST));
}


#endif

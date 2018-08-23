/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define NETDISSECT_REWORKED
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>
#include <stdlib.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "ether.h"

#define DSA_HDRLEN     16
#define DSA_TO_CPU     0
#define DSA_FROM_CPU   1
#define DSA_TO_SNIFFER 2
#define DSA_FORWARD    3

const struct tok ethertype_values[] = {
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_MPLS_MULTI,	"MPLS multicast" },
    { ETHERTYPE_IPV6,		"IPv6" },
    { ETHERTYPE_8021Q,		"802.1Q" },
    { ETHERTYPE_8021Q9100,	"802.1Q-9100" },
    { ETHERTYPE_8021QinQ,	"802.1Q-QinQ" },
    { ETHERTYPE_8021Q9200,	"802.1Q-9200" },
    { ETHERTYPE_VMAN,		"VMAN" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "ARP"},
    { ETHERTYPE_REVARP,         "Reverse ARP"},
    { ETHERTYPE_NS,             "NS" },
    { ETHERTYPE_SPRITE,         "Sprite" },
    { ETHERTYPE_TRAIL,          "Trail" },
    { ETHERTYPE_MOPDL,          "MOP DL" },
    { ETHERTYPE_MOPRC,          "MOP RC" },
    { ETHERTYPE_DN,             "DN" },
    { ETHERTYPE_LAT,            "LAT" },
    { ETHERTYPE_SCA,            "SCA" },
    { ETHERTYPE_TEB,            "TEB" },
    { ETHERTYPE_LANBRIDGE,      "Lanbridge" },
    { ETHERTYPE_DECDNS,         "DEC DNS" },
    { ETHERTYPE_DECDTS,         "DEC DTS" },
    { ETHERTYPE_VEXP,           "VEXP" },
    { ETHERTYPE_VPROD,          "VPROD" },
    { ETHERTYPE_ATALK,          "Appletalk" },
    { ETHERTYPE_AARP,           "Appletalk ARP" },
    { ETHERTYPE_IPX,            "IPX" },
    { ETHERTYPE_PPP,            "PPP" },
    { ETHERTYPE_MPCP,           "MPCP" },
    { ETHERTYPE_SLOW,           "Slow Protocols" },
    { ETHERTYPE_PPPOED,         "PPPoE D" },
    { ETHERTYPE_PPPOES,         "PPPoE S" },
    { ETHERTYPE_EAPOL,          "EAPOL" },
    { ETHERTYPE_RRCP,           "RRCP" },
    { ETHERTYPE_MS_NLB_HB,      "MS NLB heartbeat" },
    { ETHERTYPE_JUMBO,          "Jumbo" },
    { ETHERTYPE_LOOPBACK,       "Loopback" },
    { ETHERTYPE_ISO,            "OSI" },
    { ETHERTYPE_GRE_ISO,        "GRE-OSI" },
    { ETHERTYPE_CFM_OLD,        "CFM (old)" },
    { ETHERTYPE_CFM,            "CFM" },
    { ETHERTYPE_IEEE1905_1,     "IEEE1905.1" },
    { ETHERTYPE_LLDP,           "LLDP" },
    { ETHERTYPE_OUIEXT,         "OUI Extended"},
    { ETHERTYPE_TIPC,           "TIPC"},
    { ETHERTYPE_GEONET_OLD,     "GeoNet (old)"},
    { ETHERTYPE_GEONET,         "GeoNet"},
    { ETHERTYPE_CALM_FAST,      "CALM FAST"},
    { ETHERTYPE_AOE,            "AoE" },
    { ETHERTYPE_DSA,            "DSA" },
    { 0, NULL}
};

static const char *
code_name(uint8_t code)
{
	static const char *codes[] = {
		"t,bdpu",
		"r,frame2reg",
		"t,igmp",
		"t,policy",
		"m,arp",
		"m,policy",
		"UNKNOWN",
		"UNKNOWN",
	};

	return codes[code];
}

typedef struct {
	u_int8_t code;
	const char *name;
} lcode_t;

int lcode_cmp(const lcode_t *a, const lcode_t *b)
{
	return a->code - b->code;
}

static const char *
lcode_name(uint8_t code)
{
	static const lcode_t long_codes[] = {
		{   2, "t,bpdu" },
		{   3, "tm,fdb" },
		{   5, "tm,arp-bc" },
		{   6, "tm,ipv4-igmp" },
		{   8, "t,unk-src-mac" },
		{  10, "m,unk-src-mac" },
		{  13, "tm,ieee-mc-0" },
		{  14, "tm,ipv6-icmp" },
		{  16, "tm,link-local-mc-0" },
		{  17, "m,ripv1" },
		{  18, "tm,ipv6-nb-sol" },
		{  19, "tm,ipv4-bc" },
		{  20, "tm,!ipv4-bc" },
		{  21, "tm,prop-mc" },
		{  22, "tm,br-!ip-unk-mc" },
		{  23, "tm,br-ipv4-unk-mc" },
		{  24, "tm,br-ipv6-unk-mc" },
		{  25, "tm,br-unk-uc" },
		{  26, "tm,ieee-mc-1" },
		{  27, "tm,ieee-mc-2" },
		{  28, "tm,ieee-mc-3" },
		{  29, "tm,link-local-mc-1" },
		{  30, "tm,link-local-mc-2" },
		{  31, "tm,link-local-mc-3" },
		{  32, "tm,udp-bc-0" },
		{  33, "tm,udp-bc-1" },
		{  34, "tm,udp-bc-2" },
		{  35, "tm,udp-bc-3" },
		{  36, "t,sec-learn-unk-src" },
		{  64, "f,rt-packet" },
		{  65, "f,br-packet" },
		{  66, "m,sniffer-ingress" },
		{  67, "m,sniffer-egress" },
		{  68, "x,cpu-mail" },
		{  69, "x,cpu-to-cpu" },
		{  70, "m,sampled-egress" },
		{  71, "m,sampled-ingress" },
		{  74, "tm,inv-user-bytes" },
		{  75, "t,tt-ipv4-hdr-err" },
		{  76, "t,tt-ipv4-frag-err" },
		{  77, "t,tt-ipv4-gre-err" },
		{  79, "t,mpls-hdr-err" },
		{  80, "t,mpls-lsr-ttl-err" },
		{  83, "t,oam-pdu" },
		{ 133, "tm,rt-ipv4-ttl-err" },
		{ 134, "tm,rt-ipv6-mtu-err" },
		{ 135, "tm,rt-ipv6-hop-err" },
		{ 136, "tm,rt-ip-addr-err" },
		{ 137, "tm,rt-ipv4-hdr-err" },
		{ 138, "tm,rt-ip-dip-da-err" },
		{ 139, "tm,rt-ipv6-hdr-err" },
		{ 140, "tm,rt-ip-uc-sip-sa-err" },
		{ 141, "tm,rt-ipv4-opt" },
		{ 142, "tm,rt-ipv6-!hbh-opt" },
		{ 143, "tm,rt-ipv6-hbh-opt" },
		{ 159, "tm,rt-ipv6-scope" },
		{ 160, "tm,rt-ipv4-uc-0" },
		{ 161, "tm,rt-ipv4-uc-1" },
		{ 162, "tm,rt-ipv4-uc-2" },
		{ 163, "tm,rt-ipv4-uc-3" },
		{ 164, "tm,rt-ipv4-mc-0" },
		{ 165, "tm,rt-ipv4-mc-1" },
		{ 166, "tm,rt-ipv4-mc-2" },
		{ 167, "tm,rt-ipv4-mc-3" },
		{ 168, "tm,rt-ipv6-uc-0" },
		{ 169, "tm,rt-ipv6-uc-1" },
		{ 170, "tm,rt-ipv6-uc-2" },
		{ 171, "tm,rt-ipv6-uc-3" },
		{ 172, "tm,rt-ipv6-mc-0" },
		{ 173, "tm,rt-ipv6-mc-1" },
		{ 174, "tm,rt-ipv6-mc-2" },
		{ 175, "tm,rt-ipv6-mc-3" },
		{ 176, "tm,rt-ip-uc-rpf" },
		{ 177, "tm,rt-ip-mc-rt-rpf" },
		{ 178, "tm,rt-ip-mc-mll-rpf" },
		{ 179, "tm,arp-bc-to-me" },
		{ 180, "m,rt-ipv4-uc-icmp-redir" },
		{ 181, "m,rt-ipv6-uc-icmp-redir" },
		{ 188, "f,arp-reply-to-me" },
		{ 189, "x,cpu-to-all-cpus" },
		{ 190, "tmf,tcp-syn-to-cpu" },
		{ 191, "t,virtual-rt" }
	};
	lcode_t key = { .code = code };
	lcode_t *known;

	if (code >= 192)
		return "tmf,user";

	known = bsearch(&key, long_codes, sizeof(long_codes)/sizeof(lcode_t),
			sizeof(lcode_t), (__compar_fn_t)lcode_cmp);
	if (known)
		return known->name;

	return "RESERVED";
}

static void
dsa_print(netdissect_options *ndo, uint32_t tag, uint32_t *etag)
{
	uint8_t port;

	if (ndo->ndo_vflag >= 2) {
		ND_PRINT((ndo, "[%8.8x%s%c", tag, etag? "" : "]", etag? '-' : ' '));

		if (etag)
			ND_PRINT((ndo, "%8.8x] ", *etag));
	}

	port = (tag >> 19) & 0x1f;

	switch (tag >> 30) {
	case DSA_TO_CPU:
		ND_PRINT((ndo, "  to_cpu"));

		if (ndo->ndo_vflag >= 1) {
			if (etag) {
				uint8_t code = *etag & 0xff;
				ND_PRINT((ndo, "(%d:%s)", code, lcode_name(code)));
			} else {
				uint8_t code = (tag >> 17) & 0x3;
				ND_PRINT((ndo, "(%d:%s)", code, code_name(code)));
			}
		}

		if (etag)
			port += (*etag & (1 << 10)) ? (1 << 5) : 0;
		break;

	case DSA_TO_SNIFFER:
		ND_PRINT((ndo, "to_sniff"));
		break;

	case DSA_FROM_CPU:
		ND_PRINT((ndo, "from_cpu"));
		break;

	case DSA_FORWARD:
		ND_PRINT((ndo, " forward"));
		if (ndo->ndo_vflag)
			ND_PRINT((ndo, (tag & 0x00040000)? "(trunk)" : "(port)"));

		if (etag)
			port += (*etag & (1 << 29)) ? (1 << 5) : 0;
		break;
	}

	ND_PRINT((ndo, " %d/%d:vlan%d-%c%s, ",
		  (tag >> 24) &  0x1f, port,
		  (tag >>  0) & 0xfff, (tag & 0x20000000) ? 't' : 'u',
		  (((tag >> 30) == DSA_TO_SNIFFER)?
		   ((tag & 0x00040000)? " (rx)":" (tx)") : "")));
}

static inline void
ether_hdr_print(netdissect_options *ndo,
                const u_char *bp, u_int length)
{
	register const struct ether_header *ep;
	uint16_t ether_type;

	ep = (const struct ether_header *)bp;

	ND_PRINT((ndo, "%s > %s",
		     etheraddr_string(ndo, ESRC(ep)),
		     etheraddr_string(ndo, EDST(ep))));

	ether_type = EXTRACT_16BITS(&ep->ether_type);
	if ((ndo->ndo_packettype == PT_DSA) ||
	    (ndo->ndo_packettype == PT_DSA_RT))
		ether_type = EXTRACT_16BITS(&bp[DSA_HDRLEN]);

	if (!ndo->ndo_qflag) {
	        if (ether_type <= ETHERMTU)
		          ND_PRINT((ndo, ", 802.3"));
                else
		          ND_PRINT((ndo, ", ethertype %s (0x%04x)",
				       tok2str(ethertype_values,"Unknown", ether_type),
                                       ether_type));
        } else {
                if (ether_type <= ETHERMTU)
                          ND_PRINT((ndo, ", 802.3"));
                else
                          ND_PRINT((ndo, ", %s", tok2str(ethertype_values,"Unknown Ethertype (0x%04x)", ether_type)));
        }

	ND_PRINT((ndo, ", length %u: ", length));
}

/*
 * Print an Ethernet frame.
 * This might be encapsulated within another frame; we might be passed
 * a pointer to a function that can print header information for that
 * frame's protocol, and an argument to pass to that function.
 */
void
ether_print(netdissect_options *ndo,
            const u_char *p, u_int length, u_int caplen,
            void (*print_encap_header)(netdissect_options *ndo, const u_char *), const u_char *encap_header_arg)
{
	struct ether_header *ep;
	u_int orig_length;
	u_short ether_type;
	u_short extracted_ether_type;

	/* skip DSA router header  */
	if (ndo->ndo_packettype == PT_DSA_RT) {
		length -= 2;
		caplen -= 2;
		p += 2;
	}

	if (caplen < ETHER_HDRLEN || length < ETHER_HDRLEN) {
		ND_PRINT((ndo, "[|ether]"));
		return;
	}

	if (ndo->ndo_eflag) {
		if (print_encap_header != NULL)
			(*print_encap_header)(ndo, encap_header_arg);
		ether_hdr_print(ndo, p, length);
	}
	orig_length = length;

	length -= ETHER_HDRLEN;
	caplen -= ETHER_HDRLEN;
	ep = (struct ether_header *)p;
	p += ETHER_HDRLEN;

	ether_type = EXTRACT_16BITS(&ep->ether_type);

	if ((ether_type == ETHERTYPE_DSA) ||
	    (ndo->ndo_packettype == PT_DSA) ||
	    (ndo->ndo_packettype == PT_DSA_RT))
        {
           u_int32_t tag, etag = 0;
           int taglen = 4;

           if (ether_type == ETHERTYPE_DSA)
              tag = EXTRACT_32BITS((p + 2));
           else
              tag = EXTRACT_32BITS(&p[12 - ETHER_HDRLEN]);

	   if (caplen < DSA_HDRLEN || length < DSA_HDRLEN) {
		   ND_PRINT((ndo, "[|dsa]"));
		   return;
	   }

	   /* tag is extended if cpu-code is 0xf in TO_CPU, or if
	    * bit 12 is set in any other tag. */
	   if ((((tag >> 30) == DSA_TO_CPU) &&
		(tag & 0x00071000 == 0x00071000)) ||
	       (tag & (1 << 12))) {
		   taglen += 4;
		   etag = EXTRACT_32BITS(&p[16 - ETHER_HDRLEN]);
		   dsa_print(ndo, tag, &etag);
	   } else {
		   dsa_print(ndo, tag, NULL);
	   }

	   ether_type = EXTRACT_16BITS(&p[12 - ETHER_HDRLEN + taglen]);
	   p += taglen;
	   length -= taglen;
	   caplen -= taglen;
	}

recurse:
	/*
	 * Is it (gag) an 802.3 encapsulation?
	 */
	if (ether_type <= ETHERMTU) {
		if (wmo_frntv0_print(ndo, (u_char *)ep, p, length) != 0)
			return;

		/* Try to print the LLC-layer header & higher layers */
		if (llc_print(ndo, p, length, caplen, ESRC(ep), EDST(ep),
		    &extracted_ether_type) == 0) {
			/* ether_type not known, print raw packet */
			if (!ndo->ndo_eflag) {
				if (print_encap_header != NULL)
					(*print_encap_header)(ndo, encap_header_arg);
				ether_hdr_print(ndo, (u_char *)ep, orig_length);
			}

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
		}
	} else if (ether_type == ETHERTYPE_8021Q  ||
                ether_type == ETHERTYPE_8021Q9100 ||
                ether_type == ETHERTYPE_8021Q9200 ||
                ether_type == ETHERTYPE_8021QinQ) {
		/*
		 * Print VLAN information, and then go back and process
		 * the enclosed type field.
		 */
		if (caplen < 4 || length < 4) {
			ND_PRINT((ndo, "[|vlan]"));
			return;
		}
	        if (ndo->ndo_eflag) {
	        	uint16_t tag = EXTRACT_16BITS(p);

			ND_PRINT((ndo, "vlan %u, p %u%s, ",
			    tag & 0xfff,
			    tag >> 13,
			    (tag & 0x1000) ? ", CFI" : ""));
		}

		ether_type = EXTRACT_16BITS(p + 2);
		if (ndo->ndo_eflag && ether_type > ETHERMTU)
			ND_PRINT((ndo, "ethertype %s, ", tok2str(ethertype_values,"0x%04x", ether_type)));
		p += 4;
		length -= 4;
		caplen -= 4;
		goto recurse;
	} else if (ether_type == ETHERTYPE_JUMBO) {
		/*
		 * Alteon jumbo frames.
		 * See
		 *
		 *	http://tools.ietf.org/html/draft-ietf-isis-ext-eth-01
		 *
		 * which indicates that, following the type field,
		 * there's an LLC header and payload.
		 */
		/* Try to print the LLC-layer header & higher layers */
		if (llc_print(ndo, p, length, caplen, ESRC(ep), EDST(ep),
		    &extracted_ether_type) == 0) {
			/* ether_type not known, print raw packet */
			if (!ndo->ndo_eflag) {
				if (print_encap_header != NULL)
					(*print_encap_header)(ndo, encap_header_arg);
				ether_hdr_print(ndo, (u_char *)ep, orig_length);
			}

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
		}
	} else {
		if (ethertype_print(ndo, ether_type, p, length, caplen) == 0) {
			/* ether_type not known, print raw packet */
			if (!ndo->ndo_eflag) {
				if (print_encap_header != NULL)
					(*print_encap_header)(ndo, encap_header_arg);
				ether_hdr_print(ndo, (u_char *)ep, orig_length);
			}

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p, caplen);
		}
	}
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
u_int
ether_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
               const u_char *p)
{
	ether_print(ndo, p, h->len, h->caplen, NULL, NULL);

	return (ETHER_HDRLEN);
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 *
 * This is for DLT_NETANALYZER, which has a 4-byte pseudo-header
 * before the Ethernet header.
 */
u_int
netanalyzer_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
                     const u_char *p)
{
	/*
	 * Fail if we don't have enough data for the Hilscher pseudo-header.
	 */
	if (h->len < 4 || h->caplen < 4) {
		ND_PRINT((ndo, "[|netanalyzer]"));
		return (h->caplen);
	}

	/* Skip the pseudo-header. */
	ether_print(ndo, p + 4, h->len - 4, h->caplen - 4, NULL, NULL);

	return (4 + ETHER_HDRLEN);
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 *
 * This is for DLT_NETANALYZER_TRANSPARENT, which has a 4-byte
 * pseudo-header, a 7-byte Ethernet preamble, and a 1-byte Ethernet SOF
 * before the Ethernet header.
 */
u_int
netanalyzer_transparent_if_print(netdissect_options *ndo,
                                 const struct pcap_pkthdr *h,
                                 const u_char *p)
{
	/*
	 * Fail if we don't have enough data for the Hilscher pseudo-header,
	 * preamble, and SOF.
	 */
	if (h->len < 12 || h->caplen < 12) {
		ND_PRINT((ndo, "[|netanalyzer-transparent]"));
		return (h->caplen);
	}

	/* Skip the pseudo-header, preamble, and SOF. */
	ether_print(ndo, p + 12, h->len - 12, h->caplen - 12, NULL, NULL);

	return (12 + ETHER_HDRLEN);
}

/*
 * Prints the packet payload, given an Ethernet type code for the payload's
 * protocol.
 *
 * Returns non-zero if it can do so, zero if the ethertype is unknown.
 */

int
ethertype_print(netdissect_options *ndo,
                u_short ether_type, const u_char *p,
                u_int length, u_int caplen)
{
	switch (ether_type) {

	case ETHERTYPE_IP:
	        ip_print(ndo, p, length);
		return (1);

#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_print(ndo, p, length);
		return (1);
#endif /*INET6*/

	case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
  	        arp_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_DN:
		decnet_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_ATALK:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo, "et1 "));
		atalk_print(ndo, p, length);
		return (1);

	case ETHERTYPE_AARP:
		aarp_print(ndo, p, length);
		return (1);

	case ETHERTYPE_IPX:
		ND_PRINT((ndo, "(NOV-ETHII) "));
		ipx_print(ndo, p, length);
		return (1);

	case ETHERTYPE_ISO:
		isoclns_print(ndo, p + 1, length - 1, length - 1);
		return(1);

	case ETHERTYPE_PPPOED:
	case ETHERTYPE_PPPOES:
	case ETHERTYPE_PPPOED2:
	case ETHERTYPE_PPPOES2:
		pppoe_print(ndo, p, length);
		return (1);

	case ETHERTYPE_EAPOL:
	        eap_print(ndo, p, length);
		return (1);

	case ETHERTYPE_RRCP:
	        rrcp_print(ndo, p - 14 , length + 14);
		return (1);

	case ETHERTYPE_PPP:
		if (length) {
			ND_PRINT((ndo, ": "));
			ppp_print(ndo, p, length);
		}
		return (1);

	case ETHERTYPE_MPCP:
	        mpcp_print(ndo, p, length);
		return (1);

	case ETHERTYPE_SLOW:
	        slow_print(ndo, p, length);
		return (1);

	case ETHERTYPE_CFM:
	case ETHERTYPE_CFM_OLD:
		cfm_print(ndo, p, length);
		return (1);

	case ETHERTYPE_LLDP:
		lldp_print(ndo, p, length);
		return (1);

        case ETHERTYPE_LOOPBACK:
		loopback_print(ndo, p, length);
                return (1);

	case ETHERTYPE_MPLS:
	case ETHERTYPE_MPLS_MULTI:
		mpls_print(ndo, p, length);
		return (1);

	case ETHERTYPE_OUIEXT:
		snap_print(ndo, p, length, caplen, 0);
		return (1);

	case ETHERTYPE_TIPC:
		tipc_print(ndo, p, length, caplen);
		return (1);

	case ETHERTYPE_MS_NLB_HB:
		msnlb_print(ndo, p);
		return (1);

        case ETHERTYPE_GEONET_OLD:
        case ETHERTYPE_GEONET:
                geonet_print(ndo, p-14, p, length);
                return (1);

        case ETHERTYPE_CALM_FAST:
                calm_fast_print(ndo, p-14, p, length);
                return (1);

	case ETHERTYPE_AOE:
		aoe_print(ndo, p, length);
		return (1);

	case ETHERTYPE_LAT:
	case ETHERTYPE_SCA:
	case ETHERTYPE_MOPRC:
	case ETHERTYPE_MOPDL:
	case ETHERTYPE_IEEE1905_1:
		/* default_print for now */
	default:
		return (0);
	}
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */


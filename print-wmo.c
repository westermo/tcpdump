#define NETDISSECT_REWORKED
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <string.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"
#include "ether.h"
#include "llc.h"

#define FRNT0_PKTS        \
       FRNT0_PKT(ring_m)  \
       FRNT0_PKT(ring_n)  \
       FRNT0_PKT(clear_m) \
       FRNT0_PKT(clear_n) \
       FRNT0_PKT(trig)    \
       FRNT0_PKT(down_n)  \
       FRNT0_PKT(up_n)    \
       FRNT0_PKT(down_m)  \
       FRNT0_PKT(up_m)    \
       FRNT0_PKT(htrig_m) \
       FRNT0_PKT(htrig_n) \
       FRNT0_PKT(hresp_m) \
       FRNT0_PKT(hresp_n) \
       FRNT0_PKT(max)

enum frnt0_pkt_type {
#define FRNT0_PKT(_name) frnt0_pkt_ ## _name,
       FRNT0_PKTS
#undef FRNT0_PKT
};

static const char *frnt0_cmd_name[] = {
#define FRNT0_PKT(_name) #_name,
       FRNT0_PKTS
#undef FRNT0_PKT
};

static char frnt0_cmd_data[][4] = {
	[frnt0_pkt_ring_m]  = { 0x4f, 0xab, 0x30, 0x00 },
	[frnt0_pkt_ring_n]  = { 0x51, 0x9a, 0xb4, 0xcf },
	[frnt0_pkt_clear_m] = { 0x38, 0x9e, 0x00, 0xc2 },
	[frnt0_pkt_clear_n] = { 0x08, 0x12, 0xba, 0xec },
	[frnt0_pkt_trig]    = { 0xd3, 0xd3, 0x17, 0x90 },
	[frnt0_pkt_down_n]  = { 0x56, 0x8a, 0xbb, 0xb2 },
	[frnt0_pkt_up_n]    = { 0x65, 0xc2, 0xc3, 0xaa },
	[frnt0_pkt_down_m]  = { 0x49, 0x97, 0xac, 0x03 },
	[frnt0_pkt_up_m]    = { 0x1f, 0x09, 0xa2, 0x9c },
	[frnt0_pkt_htrig_m] = { 0xbf, 0x10, 0x04, 0xc1 },
	[frnt0_pkt_htrig_n] = { 0x09, 0xdd, 0xb6, 0xa4 },
	[frnt0_pkt_hresp_m] = { 0xa0, 0x28, 0x33, 0xd1 },
	[frnt0_pkt_hresp_n] = { 0x13, 0x34, 0xbc, 0x20 },
};

const u_char frnt0_mac[] = { 0x01, 0x00, 0x5e, 0x05, 0x0a, 0x00 };

int
wmo_frntv0_print(netdissect_options *ndo, const u_char *ep,
		 const u_char *p, u_int length)
{
	int type;

	if (memcmp(ep, frnt0_mac, ETHER_ADDR_LEN - 1))
		return 0;

	for (type = 0; type < frnt0_pkt_max; type++) {
		if (!memcmp(p, frnt0_cmd_data[type], 4)) {
			ND_PRINT((ndo, "FRNT %s%s",
				  ndo->ndo_vflag? "v0 ": "",
				  frnt0_cmd_name[type]));
			return 1;
		}
	}
		
	return 0;
}

enum frnt_type {
	FRNT_CLEAR_MAC = 0x06,
};

static int
wmo_frnt_print(netdissect_options *ndo, const u_char *p, u_int length)
{
	ND_PRINT((ndo, "FRNT"));
	if (ndo->ndo_vflag)
		ND_PRINT((ndo, " v%u", p[0]));

	switch (p[1]) {
	case FRNT_CLEAR_MAC:
		ND_PRINT((ndo, " clear_mac"));
		break;
	default:
		ND_PRINT((ndo, " unknown type 0x%2.2x", p[1]));
		break;
	}

	return 1;
}

enum rico_type {
	RICO_HELLO = 0x01,
	RICO_ECHO_REQ = 0x03,
	RICO_ECHO_RES = 0x04,
};

struct rico_port {
	uint32_t id;
	char     description[16];
} UNALIGNED;

struct rico_hello {
	uint16_t flags;
#define RICO_HELLO_F (1 <<  0)
#define RICO_HELLO_M (1 << 15)
	uint16_t resvd;
	uint16_t ival_configured;
	uint16_t ival_effective;
	uint32_t link_cost;
	uint16_t prio;
	uint8_t  base_mac[ETHER_ADDR_LEN];
	struct rico_port port;
} UNALIGNED;

struct rico_echo_req {
	uint16_t flags;
#define RICO_ECHO_REQ_F (1 <<  0)
	uint16_t resvd;
	uint16_t ival;
	uint8_t  base_mac[ETHER_ADDR_LEN];
	struct rico_port port;
} UNALIGNED;

struct rico_echo_res {
	uint16_t flags;
#define RICO_ECHO_RES_S (1 <<  0)
	uint16_t resvd;
	uint16_t ival;
	uint8_t  base_mac[ETHER_ADDR_LEN];
	struct rico_port port;
} UNALIGNED;

struct rico_pkt {
	uint8_t version;
	uint8_t type;
	uint8_t ring_id;
	uint8_t inst_id;

	union {
		struct rico_hello    hello;
		struct rico_echo_req echo_req;
		struct rico_echo_res echo_res;
	} u;
} UNALIGNED;

static void wmo_rico_src_print(netdissect_options *ndo,
			       const uint8_t *mac, const struct rico_port *p)
{
	uint32_t id = EXTRACT_32BITS(&p->id);

	ND_PRINT((ndo, ", mac %s",
		  etheraddr_string(ndo, mac)));

	if (id == 0x80000000)
		ND_PRINT((ndo, ", port none"));
	else
		ND_PRINT((ndo, ", port %u", id));

	ND_PRINT((ndo, "(%s)", p->description));
}

static void
wmo_rico_hello_print(netdissect_options *ndo, const struct rico_hello *h)
{
	uint16_t flags;

	flags = EXTRACT_16BITS(&h->flags);
	ND_PRINT((ndo, ", hello [%s%s]",
		  (flags & RICO_HELLO_F) ? "F" : "",
		  (flags & RICO_HELLO_M) ? "M" : ""));

	wmo_rico_src_print(ndo, h->base_mac, &h->port);

	if (ndo->ndo_vflag) {
		uint16_t prio, ival_conf, ival_eff;
		uint32_t cost;

		cost = EXTRACT_32BITS(&h->link_cost);
		prio = EXTRACT_16BITS(&h->prio);

		if (cost == UINT32_MAX && prio == UINT16_MAX)
			ND_PRINT((ndo, ", cost infinite"));
		else
			ND_PRINT((ndo, ", cost %u:%u", cost, prio));

		ival_conf = EXTRACT_16BITS(&h->ival_configured);
		ival_eff  = EXTRACT_16BITS(&h->ival_effective);
		
		ND_PRINT((ndo, ", interval %u", ival_eff));

		if (ival_eff != ival_conf)
			ND_PRINT((ndo, "(configured %u)", ival_conf));
	}
}

static void
wmo_rico_echo_req_print(netdissect_options *ndo, const struct rico_echo_req *r)
{
	uint16_t flags;

	flags = EXTRACT_16BITS(&r->flags);
	ND_PRINT((ndo, ", echo? [%s]", (flags & RICO_ECHO_REQ_F) ? "F" : ""));

	wmo_rico_src_print(ndo, r->base_mac, &r->port);

	if (ndo->ndo_vflag)		
		ND_PRINT((ndo, ", interval %u", EXTRACT_16BITS(&r->ival)));
}

static void
wmo_rico_echo_res_print(netdissect_options *ndo, const struct rico_echo_res *r)
{
	uint16_t flags;

	flags = EXTRACT_16BITS(&r->flags);
	ND_PRINT((ndo, ", echo! [%s]", (flags & RICO_ECHO_RES_S) ? "S" : ""));

	wmo_rico_src_print(ndo, r->base_mac, &r->port);
}

static int
wmo_rico_print(netdissect_options *ndo, const u_char *p, u_int length)
{
	const struct rico_pkt *pkt = (void *)p;

	ND_PRINT((ndo, "RiCo"));
	if (ndo->ndo_vflag)
		ND_PRINT((ndo, " v%u", pkt->version));

	ND_PRINT((ndo, " %u/%u", pkt->ring_id, pkt->inst_id));

	switch (pkt->type) {
	case RICO_HELLO:
		wmo_rico_hello_print(ndo, &pkt->u.hello);
		break;
	case RICO_ECHO_REQ:
		wmo_rico_echo_req_print(ndo, &pkt->u.echo_req);
		break;
	case RICO_ECHO_RES:
		wmo_rico_echo_res_print(ndo, &pkt->u.echo_res);
		break;
	default:
		ND_PRINT((ndo, " unknown type 0x%2.2x", pkt->type));
		break;
	}

	return 1;
}

int
wmo_snap_print(netdissect_options *ndo, u_short proto,
	       const u_char *p, u_int length)
{
	switch (proto) {
	case PID_WESTERMO_FRNT:
		return wmo_frnt_print(ndo, p, length);
	case PID_WESTERMO_RICO:
		return wmo_rico_print(ndo, p, length);
	}

	return 0;
}

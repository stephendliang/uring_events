#pragma once

#include "core.h"

#include <linux/io_uring.h>

// Endian-safe IPv4 literal (x86 little-endian)
#define DNS_IPV4(a,b,c,d) \
    ((u32)(a) | ((u32)(b) << 8) | ((u32)(c) << 16) | ((u32)(d) << 24))

#define DNS_SERVER_CLOUDFLARE   DNS_IPV4(1,1,1,1)
#define DNS_SERVER_CLOUDFLARE2  DNS_IPV4(1,0,0,1)
#define DNS_SERVER_GOOGLE       DNS_IPV4(8,8,8,8)
#define DNS_SERVER_GOOGLE2      DNS_IPV4(8,8,4,4)

// DNS protocol constants
#define DNS_PORT            53
#define DNS_MAX_NAME_LEN    255
#define DNS_MAX_LABEL_LEN   63
#define DNS_HEADER_SIZE     12
#define DNS_MAX_PACKET      512

#define DNS_TYPE_A          1
#define DNS_TYPE_CNAME      5
#define DNS_CLASS_IN        1

#define DNS_FLAG_QR         0x8000
#define DNS_FLAG_TC         0x0200
#define DNS_FLAG_RD         0x0100
#define DNS_FLAG_RCODE      0x000F

// Op codes for user_data encoding
enum dns_op {
    DNS_OP_SEND = 0,
    DNS_OP_RECV = 1,
};

// SQE templates — 64-byte aligned for SIMD copy via PREP_SQE
#define CACHE_ALIGN __attribute__((aligned(64)))

CACHE_ALIGN
static const struct io_uring_sqe DNS_SQE_TEMPLATE_SEND = {
    .opcode = IORING_OP_SENDMSG,
    .len    = 1,
};

CACHE_ALIGN
static const struct io_uring_sqe DNS_SQE_TEMPLATE_RECV = {
    .opcode = IORING_OP_RECVMSG,
    .ioprio = IORING_RECV_MULTISHOT,
    .flags  = IOSQE_BUFFER_SELECT,
    .len    = 0,
};

// Resolver context
typedef struct {
    int fd;
    u16 id_counter;
} dns_ctx;

// Cold path — socket setup / teardown
int  dns_init(dns_ctx *ctx, u32 server_ip);
void dns_close(dns_ctx *ctx);

// Build DNS query packet into buf. Returns packet length or -1.
int dns_build_query(dns_ctx *ctx, const char *hostname,
                    u8 *buf, u32 buf_len, u16 *txn_id_out);

// Parse response. Returns address count (>0), 0 (NXDOMAIN), -1 (error).
int dns_parse_response(const u8 *pkt, u32 pkt_len, u16 expected_txn_id,
                       u32 *addrs, int max_addrs);

// Parse with CNAME extraction. If return is 0 and cname_out[0] != '\0',
// caller should re-query for the CNAME target.
int dns_parse_response_cname(const u8 *pkt, u32 pkt_len, u16 expected_txn_id,
                             u32 *addrs, int max_addrs,
                             char *cname_out, u32 cname_buf_len);

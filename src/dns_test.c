#define NOLIBC_MAIN

#include "dns.c"  // pull in implementation for static functions

// --- Test harness ---

static int tests_run;
static int tests_passed;

#define ASSERT(cond, msg) do {                                          \
    tests_run++;                                                        \
    if (!(cond)) {                                                      \
        _fmt_write(2, "  FAIL: %s (line %d)\n", msg, __LINE__);        \
        return 0;                                                       \
    }                                                                   \
    tests_passed++;                                                     \
    return 1;                                                           \
} while (0)

#define RUN(fn) do {                                    \
    if (fn()) _fmt_write(2, "  ok   %s\n", #fn);       \
    else      _fmt_write(2, "  FAIL %s\n", #fn);       \
} while (0)

// --- Helper: build a DNS response packet by hand ---

// Write a name as a sequence of labels into buf at *pos, update *pos.
static void pkt_write_name(u8 *buf, u32 *pos, const char *name) {
    const char *p = name;
    while (*p) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        u8 len = (u8)(dot - p);
        buf[(*pos)++] = len;
        for (u8 i = 0; i < len; i++)
            buf[(*pos)++] = (u8)p[i];
        p = *dot ? dot + 1 : dot;
    }
    buf[(*pos)++] = 0;
}

// Write big-endian u16
static void pkt_put16(u8 *buf, u32 *pos, u16 val) {
    buf[(*pos)++] = (u8)(val >> 8);
    buf[(*pos)++] = (u8)(val);
}

// Write big-endian u32
static void pkt_put32(u8 *buf, u32 *pos, u32 val) {
    buf[(*pos)++] = (u8)(val >> 24);
    buf[(*pos)++] = (u8)(val >> 16);
    buf[(*pos)++] = (u8)(val >> 8);
    buf[(*pos)++] = (u8)(val);
}

// Write raw bytes
static void pkt_putraw(u8 *buf, u32 *pos, const u8 *src, u32 n) {
    for (u32 i = 0; i < n; i++)
        buf[(*pos)++] = src[i];
}

static int str_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

// Build a minimal DNS response header.
//   id, flags, qdcount, ancount, nscount=0, arcount=0
static void pkt_write_header(u8 *buf, u32 *pos,
                              u16 id, u16 flags, u16 qdcount, u16 ancount) {
    pkt_put16(buf, pos, id);
    pkt_put16(buf, pos, flags);
    pkt_put16(buf, pos, qdcount);
    pkt_put16(buf, pos, ancount);
    pkt_put16(buf, pos, 0);  // nscount
    pkt_put16(buf, pos, 0);  // arcount
}

// Write a question section entry (name + type + class)
static void pkt_write_question(u8 *buf, u32 *pos,
                                const char *name, u16 type, u16 class) {
    pkt_write_name(buf, pos, name);
    pkt_put16(buf, pos, type);
    pkt_put16(buf, pos, class);
}

// Write an A record answer (name as compression pointer, TTL=300)
static void pkt_write_a_record(u8 *buf, u32 *pos,
                                u16 name_ptr, u32 ip) {
    // Compression pointer to name
    pkt_put16(buf, pos, 0xC000 | name_ptr);
    pkt_put16(buf, pos, DNS_TYPE_A);
    pkt_put16(buf, pos, DNS_CLASS_IN);
    pkt_put32(buf, pos, 300);  // TTL
    pkt_put16(buf, pos, 4);    // rdlength
    pkt_putraw(buf, pos, (const u8 *)&ip, 4);  // already in network order
}

// Write an A record answer with owner encoded inline.
static void pkt_write_a_record_named(u8 *buf, u32 *pos,
                                     const char *owner, u32 ip) {
    pkt_write_name(buf, pos, owner);
    pkt_put16(buf, pos, DNS_TYPE_A);
    pkt_put16(buf, pos, DNS_CLASS_IN);
    pkt_put32(buf, pos, 300);  // TTL
    pkt_put16(buf, pos, 4);    // rdlength
    pkt_putraw(buf, pos, (const u8 *)&ip, 4);  // already in network order
}

// Write a CNAME answer (name as compression pointer, target as labels)
static void pkt_write_cname(u8 *buf, u32 *pos,
                             u16 name_ptr, const char *target) {
    pkt_put16(buf, pos, 0xC000 | name_ptr);
    pkt_put16(buf, pos, DNS_TYPE_CNAME);
    pkt_put16(buf, pos, DNS_CLASS_IN);
    pkt_put32(buf, pos, 300);  // TTL

    // Need to know rdlength before writing target — measure first
    u32 rdstart = *pos;
    pkt_put16(buf, pos, 0);    // placeholder
    u32 tgt_start = *pos;
    pkt_write_name(buf, pos, target);
    u16 rdlen = (u16)(*pos - tgt_start);
    buf[rdstart]     = (u8)(rdlen >> 8);
    buf[rdstart + 1] = (u8)(rdlen);
}

// ====================================================================
// Tests: dns_build_query
// ====================================================================

static int test_build_query_basic(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0 };
    u8 buf[DNS_MAX_PACKET];
    u16 txn_id;

    int len = dns_build_query(&ctx, "example.com", buf, sizeof(buf), &txn_id);
    ASSERT(len > 0 && txn_id == 1, "build_query returns positive length and increments id");
}

static int test_build_query_wire_format(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0x00FF };
    u8 buf[DNS_MAX_PACKET];
    u16 txn_id;

    int len = dns_build_query(&ctx, "a.bc", buf, sizeof(buf), &txn_id);
    // Header: id=0x0100, flags=0x0100(RD), qdcount=1, ancount=0, nscount=0, arcount=0
    // Name: 01 'a' 02 'b' 'c' 00
    // QTYPE=1 QCLASS=1
    ASSERT(len == DNS_HEADER_SIZE + 6 + 4 && txn_id == 0x0100,
           "build_query wire bytes for 'a.bc'");
}

static int test_build_query_header_fields(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0x1233 };
    u8 buf[DNS_MAX_PACKET];
    u16 txn_id;

    dns_build_query(&ctx, "test.com", buf, sizeof(buf), &txn_id);

    // Verify header: id, flags(RD), qdcount=1
    u16 pkt_id    = (u16)(buf[0] << 8 | buf[1]);
    u16 flags     = (u16)(buf[2] << 8 | buf[3]);
    u16 qdcount   = (u16)(buf[4] << 8 | buf[5]);
    u16 ancount   = (u16)(buf[6] << 8 | buf[7]);
    ASSERT(pkt_id == 0x1234 && flags == DNS_FLAG_RD && qdcount == 1 && ancount == 0,
           "header has correct id, RD flag, qdcount=1, ancount=0");
}

static int test_build_query_trailing_type_class(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0 };
    u8 buf[DNS_MAX_PACKET];
    u16 txn_id;

    int len = dns_build_query(&ctx, "x.y", buf, sizeof(buf), &txn_id);
    // Last 4 bytes: TYPE_A=0x0001, CLASS_IN=0x0001
    u16 qtype  = (u16)(buf[len - 4] << 8 | buf[len - 3]);
    u16 qclass = (u16)(buf[len - 2] << 8 | buf[len - 1]);
    ASSERT(qtype == DNS_TYPE_A && qclass == DNS_CLASS_IN,
           "query ends with TYPE_A and CLASS_IN");
}

static int test_build_query_buf_too_small(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0 };
    u8 buf[16];  // too small for header + name + type/class
    u16 txn_id;

    int len = dns_build_query(&ctx, "example.com", buf, sizeof(buf), &txn_id);
    ASSERT(len == -1, "build_query returns -1 for undersized buffer");
}

static int test_build_query_sequential_ids(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0 };
    u8 buf[DNS_MAX_PACKET];
    u16 id1, id2, id3;

    dns_build_query(&ctx, "a.com", buf, sizeof(buf), &id1);
    dns_build_query(&ctx, "b.com", buf, sizeof(buf), &id2);
    dns_build_query(&ctx, "c.com", buf, sizeof(buf), &id3);
    ASSERT(id1 == 1 && id2 == 2 && id3 == 3, "txn IDs increment sequentially");
}

// ====================================================================
// Tests: dns_parse_response — single A record
// ====================================================================

static int test_parse_single_a(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xABCD;
    u32 expect_ip = DNS_IPV4(93,184,216,34);

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, expect_ip);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 1 && addrs[0] == expect_ip, "parse single A record");
}

// ====================================================================
// Tests: dns_parse_response — multiple A records
// ====================================================================

static int test_parse_multi_a(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x1234;

    u32 ip1 = DNS_IPV4(1,2,3,4);
    u32 ip2 = DNS_IPV4(5,6,7,8);
    u32 ip3 = DNS_IPV4(9,10,11,12);

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 3);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "multi.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, ip1);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, ip2);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, ip3);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 3 && addrs[0] == ip1 && addrs[1] == ip2 && addrs[2] == ip3,
           "parse 3 A records");
}

static int test_parse_multi_a_limited(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x5555;

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 3);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "test.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, DNS_IPV4(1,1,1,1));
    pkt_write_a_record(pkt, &pos, (u16)qname_off, DNS_IPV4(2,2,2,2));
    pkt_write_a_record(pkt, &pos, (u16)qname_off, DNS_IPV4(3,3,3,3));

    u32 addrs[2];  // only room for 2
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 2);
    ASSERT(n == 2 && addrs[0] == DNS_IPV4(1,1,1,1) && addrs[1] == DNS_IPV4(2,2,2,2),
           "max_addrs limits output");
}

// ====================================================================
// Tests: dns_parse_response — NXDOMAIN
// ====================================================================

static int test_parse_nxdomain(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x9999;

    // RCODE=3 (NXDOMAIN)
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD | 3, 1, 0);
    pkt_write_question(pkt, &pos, "nope.invalid", DNS_TYPE_A, DNS_CLASS_IN);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 0, "NXDOMAIN returns 0");
}

// ====================================================================
// Tests: dns_parse_response — error cases
// ====================================================================

static int test_parse_wrong_txn_id(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;

    pkt_write_header(pkt, &pos, 0x1111, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "test.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, DNS_IPV4(1,2,3,4));

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, 0x2222, addrs, 4);
    ASSERT(n == -1, "wrong txn_id returns -1");
}

static int test_parse_no_qr_flag(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xAAAA;

    // Missing QR flag — this is a query, not a response
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_RD, 1, 0);
    pkt_write_question(pkt, &pos, "test.com", DNS_TYPE_A, DNS_CLASS_IN);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == -1, "missing QR flag returns -1");
}

static int test_parse_servfail(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xBBBB;

    // RCODE=2 (SERVFAIL)
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD | 2, 1, 0);
    pkt_write_question(pkt, &pos, "test.com", DNS_TYPE_A, DNS_CLASS_IN);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == -1, "SERVFAIL returns -1");
}

static int test_parse_truncated_header(void) {
    u8 pkt[8] = {0};  // less than DNS_HEADER_SIZE

    u32 addrs[4];
    int n = dns_parse_response(pkt, 8, 0, addrs, 4);
    ASSERT(n == -1, "truncated header returns -1");
}

static int test_parse_zero_answers(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xCCCC;

    // RCODE=0 but ancount=0 (NOERROR, no data)
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 0);
    pkt_write_question(pkt, &pos, "empty.test", DNS_TYPE_A, DNS_CLASS_IN);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 0, "zero answers returns 0");
}

static int test_parse_tc_bit_rejected(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xCCCD;

    // Truncated response (TC=1) must be rejected for UDP parser.
    pkt_write_header(pkt, &pos, txn_id,
                     DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_TC, 1, 0);
    pkt_write_question(pkt, &pos, "trunc.test", DNS_TYPE_A, DNS_CLASS_IN);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == -1, "TC bit returns -1");
}

static int test_parse_ancount_truncated_answer_fails(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xCCCE;
    u32 ip = DNS_IPV4(10,0,0,1);

    // Claims 2 answers but only encodes 1.
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 2);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "truncated.answers", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record(pkt, &pos, (u16)qname_off, ip);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == -1, "truncated answer section returns -1");
}

static int test_parse_unrelated_owner_not_accepted(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xCCCF;
    u32 ip = DNS_IPV4(11,22,33,44);

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    pkt_write_question(pkt, &pos, "wanted.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_a_record_named(pkt, &pos, "other.example.com", ip);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 0, "A answer with non-matching owner is ignored");
}

static int test_parse_non_in_class_not_accepted(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xCCD0;
    u32 ip = DNS_IPV4(44,33,22,11);

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "class.test", DNS_TYPE_A, DNS_CLASS_IN);

    pkt_put16(pkt, &pos, 0xC000 | (u16)qname_off);
    pkt_put16(pkt, &pos, DNS_TYPE_A);
    pkt_put16(pkt, &pos, 3);  // CH class
    pkt_put32(pkt, &pos, 300);
    pkt_put16(pkt, &pos, 4);
    pkt_putraw(pkt, &pos, (const u8 *)&ip, 4);

    u32 addrs[4];
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 0, "A answer with non-IN class is ignored");
}

// ====================================================================
// Tests: dns_parse_response_cname
// ====================================================================

static int test_parse_cname_then_a(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xDDDD;
    u32 expect_ip = DNS_IPV4(93,184,216,34);

    // CNAME answer followed by A record
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 2);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_cname(pkt, &pos, (u16)qname_off, "example.com");
    pkt_write_a_record_named(pkt, &pos, "example.com", expect_ip);

    u32 addrs[4];
    char cname[256];
    int n = dns_parse_response_cname(pkt, pos, txn_id, addrs, 4, cname, sizeof(cname));
    // Should return 1 A record and also extract the CNAME
    ASSERT(n == 1 && addrs[0] == expect_ip && str_eq(cname, "example.com"),
           "CNAME+A: got A record and CNAME");
}

static int test_parse_cname_only(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xEEEE;

    // Only a CNAME answer, no A record
    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "alias.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_cname(pkt, &pos, (u16)qname_off, "real.example.com");

    u32 addrs[4];
    char cname[256];
    int n = dns_parse_response_cname(pkt, pos, txn_id, addrs, 4, cname, sizeof(cname));
    ASSERT(n == 0 && cname[0] != '\0', "CNAME-only: count=0, cname populated");
}

static int test_parse_cname_not_extracted_by_basic(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0xFFFF;

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "alias.test", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_cname(pkt, &pos, (u16)qname_off, "target.test");

    u32 addrs[4];
    // dns_parse_response (not _cname) should return 0 with no CNAME output
    int n = dns_parse_response(pkt, pos, txn_id, addrs, 4);
    ASSERT(n == 0, "basic parse ignores CNAME, returns 0");
}

// ====================================================================
// Tests: DNS_IPV4 macro correctness
// ====================================================================

static int test_ipv4_macro(void) {
    u32 ip = DNS_IPV4(8,8,4,4);
    u8 *b = (u8 *)&ip;
    ASSERT(b[0] == 8 && b[1] == 8 && b[2] == 4 && b[3] == 4,
           "DNS_IPV4(8,8,4,4) has correct byte order");
}

static int test_ipv4_macro_loopback(void) {
    u32 ip = DNS_IPV4(127,0,0,1);
    u8 *b = (u8 *)&ip;
    ASSERT(b[0] == 127 && b[1] == 0 && b[2] == 0 && b[3] == 1,
           "DNS_IPV4(127,0,0,1) has correct byte order");
}

static int test_server_constants(void) {
    u8 *cf  = (u8 *)&(u32){DNS_SERVER_CLOUDFLARE};
    u8 *g   = (u8 *)&(u32){DNS_SERVER_GOOGLE};
    u8 *g2  = (u8 *)&(u32){DNS_SERVER_GOOGLE2};
    u8 *cf2 = (u8 *)&(u32){DNS_SERVER_CLOUDFLARE2};

    int ok = (cf[0]==1 && cf[1]==1 && cf[2]==1 && cf[3]==1)
          && (g[0]==8 && g[1]==8 && g[2]==8 && g[3]==8)
          && (g2[0]==8 && g2[1]==8 && g2[2]==4 && g2[3]==4)
          && (cf2[0]==1 && cf2[1]==0 && cf2[2]==0 && cf2[3]==1);
    ASSERT(ok, "all DNS_SERVER_* constants have correct byte order");
}

// ====================================================================
// Tests: compression pointer in response
// ====================================================================

static int test_parse_forward_compression_ptr(void) {
    // CNAME rdata is a forward compression pointer into answer #2 owner name.
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x4444;

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 2);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "alias.example.com", DNS_TYPE_A, DNS_CLASS_IN);

    // Answer 1: CNAME alias.example.com -> (forward pointer to answer #2 owner)
    pkt_put16(pkt, &pos, 0xC000 | (u16)qname_off);  // name: ptr to question
    pkt_put16(pkt, &pos, DNS_TYPE_CNAME);
    pkt_put16(pkt, &pos, DNS_CLASS_IN);
    pkt_put32(pkt, &pos, 300);
    pkt_put16(pkt, &pos, 2);  // rdata is one compression pointer
    u32 cname_ptr_off = pos;
    pkt_put16(pkt, &pos, 0);  // patched after answer #2 owner offset is known

    // Answer 2: A record owner encoded inline as target.example.com
    u32 target_name_off = pos;
    pkt_write_name(pkt, &pos, "target.example.com");
    pkt_put16(pkt, &pos, DNS_TYPE_A);
    pkt_put16(pkt, &pos, DNS_CLASS_IN);
    pkt_put32(pkt, &pos, 300);
    pkt_put16(pkt, &pos, 4);
    u32 ip = DNS_IPV4(10,20,30,40);
    pkt_putraw(pkt, &pos, (const u8 *)&ip, 4);

    u16 cname_ptr = (u16)(0xC000 | (u16)target_name_off);
    pkt[cname_ptr_off] = (u8)(cname_ptr >> 8);
    pkt[cname_ptr_off + 1] = (u8)cname_ptr;

    u32 addrs[4];
    char cname[256];
    int n = dns_parse_response_cname(pkt, pos, txn_id, addrs, 4, cname, sizeof(cname));
    ASSERT(n == 1 && addrs[0] == ip && str_eq(cname, "target.example.com"),
           "forward compression pointer decodes CNAME correctly");
}

static int test_parse_malformed_cname_fails(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x4445;

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "badcname.test", DNS_TYPE_A, DNS_CLASS_IN);

    // CNAME RDATA points to itself (compression loop).
    pkt_put16(pkt, &pos, 0xC000 | (u16)qname_off);
    pkt_put16(pkt, &pos, DNS_TYPE_CNAME);
    pkt_put16(pkt, &pos, DNS_CLASS_IN);
    pkt_put32(pkt, &pos, 300);
    pkt_put16(pkt, &pos, 2);
    u16 self_ptr = (u16)(0xC000 | (u16)pos);
    pkt_put16(pkt, &pos, self_ptr);

    u32 addrs[4];
    char cname[256];
    int n = dns_parse_response_cname(pkt, pos, txn_id, addrs, 4, cname, sizeof(cname));
    ASSERT(n == -1, "malformed CNAME compression returns -1");
}

static int test_parse_cname_buf_len_zero_is_safe(void) {
    u8 pkt[DNS_MAX_PACKET];
    u32 pos = 0;
    u16 txn_id = 0x4446;
    u32 ip = DNS_IPV4(20,30,40,50);

    pkt_write_header(pkt, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 2);
    u32 qname_off = pos;
    pkt_write_question(pkt, &pos, "zero.len.test", DNS_TYPE_A, DNS_CLASS_IN);
    pkt_write_cname(pkt, &pos, (u16)qname_off, "real.zero.len.test");
    pkt_write_a_record_named(pkt, &pos, "real.zero.len.test", ip);

    u32 addrs[4];
    const char *ro = "readonly";
    int n = dns_parse_response_cname(pkt, pos, txn_id, addrs, 4, (char *)ro, 0);
    ASSERT(n == 1 && addrs[0] == ip, "cname_out with len=0 does not write");
}

// ====================================================================
// Tests: build_query + parse roundtrip
// ====================================================================

static int test_roundtrip(void) {
    dns_ctx ctx = { .fd = -1, .id_counter = 0x7000 };
    u8 query[DNS_MAX_PACKET];
    u16 txn_id;

    int qlen = dns_build_query(&ctx, "roundtrip.test", query, sizeof(query), &txn_id);

    // Build a matching response reusing the question section bytes
    u8 resp[DNS_MAX_PACKET];
    u32 pos = 0;
    pkt_write_header(resp, &pos, txn_id, DNS_FLAG_QR | DNS_FLAG_RD, 1, 1);

    // Copy the question section from the query
    u32 qsection_len = (u32)qlen - DNS_HEADER_SIZE;
    u32 qname_off = pos;
    pkt_putraw(resp, &pos, query + DNS_HEADER_SIZE, qsection_len);

    u32 ip = DNS_IPV4(192,168,1,1);
    pkt_write_a_record(resp, &pos, (u16)qname_off, ip);

    u32 addrs[4];
    int n = dns_parse_response(resp, pos, txn_id, addrs, 4);
    ASSERT(n == 1 && addrs[0] == ip, "build_query -> parse_response roundtrip");
}

// ====================================================================
// Entry point
// ====================================================================

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    _fmt_write(2, "\ndns test suite\n==============\n");

    // build_query
    _fmt_write(2, "\nbuild_query:\n");
    RUN(test_build_query_basic);
    RUN(test_build_query_wire_format);
    RUN(test_build_query_header_fields);
    RUN(test_build_query_trailing_type_class);
    RUN(test_build_query_buf_too_small);
    RUN(test_build_query_sequential_ids);

    // parse_response
    _fmt_write(2, "\nparse_response:\n");
    RUN(test_parse_single_a);
    RUN(test_parse_multi_a);
    RUN(test_parse_multi_a_limited);
    RUN(test_parse_nxdomain);
    RUN(test_parse_wrong_txn_id);
    RUN(test_parse_no_qr_flag);
    RUN(test_parse_servfail);
    RUN(test_parse_truncated_header);
    RUN(test_parse_zero_answers);
    RUN(test_parse_tc_bit_rejected);
    RUN(test_parse_ancount_truncated_answer_fails);
    RUN(test_parse_unrelated_owner_not_accepted);
    RUN(test_parse_non_in_class_not_accepted);

    // parse_response_cname
    _fmt_write(2, "\nparse_response_cname:\n");
    RUN(test_parse_cname_then_a);
    RUN(test_parse_cname_only);
    RUN(test_parse_cname_not_extracted_by_basic);
    RUN(test_parse_forward_compression_ptr);
    RUN(test_parse_malformed_cname_fails);
    RUN(test_parse_cname_buf_len_zero_is_safe);

    // DNS_IPV4 macro
    _fmt_write(2, "\nDNS_IPV4:\n");
    RUN(test_ipv4_macro);
    RUN(test_ipv4_macro_loopback);
    RUN(test_server_constants);

    // roundtrip
    _fmt_write(2, "\nroundtrip:\n");
    RUN(test_roundtrip);

    _fmt_write(2, "\n%d/%d passed\n\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

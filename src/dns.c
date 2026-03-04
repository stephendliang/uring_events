#include "dns.h"
#include "nolibc.h"

// --- Wire format helpers ---

#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
    #define DNS_FAST_UNALIGNED 1
#else
    #define DNS_FAST_UNALIGNED 0
#endif

static inline u16 read_u16(const u8 *p) {
#if DNS_FAST_UNALIGNED
    u16 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return __builtin_bswap16(v);
#else
    return (u16)((p[0] << 8) | p[1]);
#endif
}

static inline void write_u32_be(u8 *p, u32 v) {
#if DNS_FAST_UNALIGNED
    u32 be = __builtin_bswap32(v);
    __builtin_memcpy(p, &be, sizeof(be));
#else
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);  p[3] = (u8)v;
#endif
}

static inline void write_u64_be(u8 *p, u64 v) {
#if DNS_FAST_UNALIGNED
    u64 be = __builtin_bswap64(v);
    __builtin_memcpy(p, &be, sizeof(be));
#else
    p[0] = (u8)(v >> 56); p[1] = (u8)(v >> 48);
    p[2] = (u8)(v >> 40); p[3] = (u8)(v >> 32);
    p[4] = (u8)(v >> 24); p[5] = (u8)(v >> 16);
    p[6] = (u8)(v >> 8);  p[7] = (u8)v;
#endif
}

static inline void write_header(u8 *buf, u16 id) {
    u64 hdr_lo = ((u64)id << 48) | ((u64)DNS_FLAG_RD << 32) | (1ULL << 16);
    write_u64_be(buf, hdr_lo);
    write_u32_be(buf + 8, 0);
}

// --- Name encoding / decoding ---

static inline u64 dns_swar_zero_mask(u64 x) {
    return (x - 0x0101010101010101ULL) & ~x & 0x8080808080808080ULL;
}

static inline u64 dns_swar_dot_mask(u64 x) {
    return dns_swar_zero_mask(x ^ 0x2E2E2E2E2E2E2E2EULL);
}

static inline const char *dns_find_label_term(const char *s, char *term_out) {
#if DNS_FAST_UNALIGNED
    const char *p = s;
    for (;;) {
        // Keep 8-byte SWAR loads within a single page to avoid cross-page faults.
        if (unlikely((((unsigned long)p) & 4095UL) > 4088UL)) {
            char c = *p;
            if (c == '.' || c == '\0') {
                *term_out = c;
                return p;
            }
            p++;
            continue;
        }

        u64 w;
        __builtin_memcpy(&w, p, sizeof(w));
        u64 mask = dns_swar_zero_mask(w) | dns_swar_dot_mask(w);
        if (mask != 0) {
            p += (u32)(__builtin_ctzll(mask) >> 3);
            *term_out = *p;
            return p;
        }
        p += 8;
    }
#else
    const char *p = s;
    while (*p != '.' && *p != '\0') p++;
    *term_out = *p;
    return p;
#endif
}

static int encode_name(const char *name, u8 *buf, u8 *buf_end) {
    u8 *out = buf;

    for (;;) {
        char term;
        const char *label_end = dns_find_label_term(name, &term);
        u32 label_len = (u32)(label_end - name);

        if (unlikely(label_len > DNS_MAX_LABEL_LEN))
            return -1;
        if (unlikely(term == '.' && label_len == 0))
            return -1;

        if (label_len > 0) {
            if (unlikely(out + 1 + label_len > buf_end))
                return -1;
            *out++ = (u8)label_len;
            __builtin_memcpy(out, name, label_len);
            out += label_len;
        }

        if (term == '\0')
            break;

        name = label_end + 1;
    }

    if (unlikely(out >= buf_end))
        return -1;
    *out++ = 0;
    return (int)(out - buf);
}

static inline int skip_name(const u8 *pkt, u32 pkt_len, u32 pos) {
    u32 start = pos;
    while (pos < pkt_len) {
        u8 len = pkt[pos];
        if ((len & 0xC0) == 0xC0) {
            if (unlikely(pos + 1 >= pkt_len)) return -1;
            return (int)(pos - start + 2);
        }
        if (len == 0) return (int)(pos - start + 1);
        if (unlikely(len > DNS_MAX_LABEL_LEN)) return -1;
        if (unlikely(pos + 1 + len > pkt_len)) return -1;
        pos += 1 + len;
    }
    return -1;
}

static int decode_name(const u8 *pkt, u32 pkt_len, u32 offset,
                       char *name, u32 name_len) {
    if (unlikely(name_len == 0)) return -1;

    u32 name_pos = 0;
    u32 pos = offset;
    int bytes_consumed = -1;
    int ptr_count = 0;

    while (pos < pkt_len && ptr_count < 16) {
        u8 len = pkt[pos];

        if ((len & 0xC0) == 0xC0) {
            if (unlikely(pos + 1 >= pkt_len)) return -1;
            if (bytes_consumed < 0) bytes_consumed = (int)(pos - offset + 2);
            pos = ((len & 0x3F) << 8) | pkt[pos + 1];
            ptr_count++;
            continue;
        }

        if (len == 0) {
            if (bytes_consumed < 0) bytes_consumed = (int)(pos - offset + 1);
            name[name_pos] = '\0';
            return bytes_consumed;
        }

        if (unlikely((len & 0xC0) != 0 || len > DNS_MAX_LABEL_LEN)) return -1;
        if (unlikely(pos + 1 + len > pkt_len)) return -1;

        if (name_pos > 0) {
            if (unlikely(name_pos >= name_len - 1)) return -1;
            name[name_pos++] = '.';
        }

        if (unlikely(name_pos + len >= name_len)) return -1;
        __builtin_memcpy(name + name_pos, pkt + pos + 1, len);
        name_pos += len;
        pos += 1 + len;
    }
    return -1;
}

static int name_eq(const char *a, const char *b) {
#if DNS_FAST_UNALIGNED
    for (;;) {
        u64 wa, wb;
        __builtin_memcpy(&wa, a, sizeof(wa));
        __builtin_memcpy(&wb, b, sizeof(wb));

        if (likely(((wa ^ wb) | dns_swar_zero_mask(wa)) == 0)) {
            a += 8;
            b += 8;
            continue;
        }

        for (int i = 0; i < 8; i++) {
            char ca = a[i];
            char cb = b[i];
            if (ca != cb) return 0;
            if (ca == '\0') return 1;
        }
    }
#else
    for (;;) {
        if (*a != *b) return 0;
        if (*a == '\0') return 1;
        a++;
        b++;
    }
#endif
}

static int name_copy(char *dst, u32 dst_len, const char *src) {
    u32 i = 0;
    if (unlikely(dst_len == 0)) return -1;

#if DNS_FAST_UNALIGNED
    while (i + 8 < dst_len) {
        u64 w;
        __builtin_memcpy(&w, src + i, sizeof(w));

        u64 zero = dns_swar_zero_mask(w);
        if (zero != 0) {
            u32 n = (u32)(__builtin_ctzll(zero) >> 3) + 1;
            __builtin_memcpy(dst + i, src + i, n);
            return 0;
        }

        __builtin_memcpy(dst + i, &w, sizeof(w));
        i += 8;
    }
#endif

    while (src[i] != '\0') {
        if (unlikely(i + 1 >= dst_len)) return -1;
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return 0;
}

// --- Cold path: socket setup / teardown ---

int dns_init(dns_ctx *ctx, u32 server_ip) {
    int fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if (unlikely(fd < 0)) return -1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
    };
    addr.sin_addr.s_addr = server_ip;

    if (unlikely(sys_connect(fd, &addr, sizeof(addr)) < 0)) {
        sys_close(fd);
        return -1;
    }

    ctx->fd = fd;
    ctx->id_counter = (u16)(unsigned long)ctx;
    return 0;
}

void dns_close(dns_ctx *ctx) {
    if (ctx->fd >= 0) {
        sys_close(ctx->fd);
        ctx->fd = -1;
    }
}

// --- Packet construction ---

int dns_build_query(dns_ctx *ctx, const char *hostname,
                    u8 *buf, u32 buf_len, u16 *txn_id_out) {
    if (unlikely(buf_len < DNS_HEADER_SIZE + 6))
        return -1;

    u16 id = ++ctx->id_counter;
    write_header(buf, id);

    int name_len = encode_name(hostname, buf + DNS_HEADER_SIZE,
                               buf + buf_len - 4);
    if (unlikely(name_len < 0)) return -1;

    u32 qlen = DNS_HEADER_SIZE + (u32)name_len;
    if (unlikely(qlen + 4 > buf_len)) return -1;

    write_u32_be(buf + qlen, ((u32)DNS_TYPE_A << 16) | DNS_CLASS_IN);
    qlen += 4;

    *txn_id_out = id;
    return (int)qlen;
}

// --- Response parsing (internal) ---

static int parse_answers(const u8 *pkt, u32 pkt_len, u16 expected_txn_id,
                         u32 *addrs, int max_addrs,
                         char *cname_out, u32 cname_buf_len) {
    if (unlikely(pkt_len < DNS_HEADER_SIZE))
        return -1;
    if (unlikely(max_addrs > 0 && addrs == NULL))
        return -1;

    u16 resp_id = read_u16(pkt);
    u16 flags   = read_u16(pkt + 2);
    u16 qdcount = read_u16(pkt + 4);
    u16 ancount = read_u16(pkt + 6);

    if (unlikely(resp_id != expected_txn_id)) return -1;
    if (unlikely(!(flags & DNS_FLAG_QR)))     return -1;
    if (unlikely(flags & DNS_FLAG_TC))        return -1;

    int rcode = flags & DNS_FLAG_RCODE;
    if (rcode == 3) return 0;  // NXDOMAIN
    if (unlikely(rcode != 0)) return -1;
    if (unlikely(qdcount == 0)) return -1;

    char qname[DNS_MAX_NAME_LEN + 1];
    char owner[DNS_MAX_NAME_LEN + 1];
    char cname_target[DNS_MAX_NAME_LEN + 1];
    const char *expected_name = qname;

    // Skip question section
    u32 pos = DNS_HEADER_SIZE;
    for (int i = 0; i < qdcount; i++) {
        int name_len = (i == 0)
            ? decode_name(pkt, pkt_len, pos, qname, sizeof(qname))
            : skip_name(pkt, pkt_len, pos);
        if (unlikely(name_len < 0)) return -1;
        pos += (u32)name_len;
        if (unlikely(pos + 4 > pkt_len)) return -1;

        u16 qtype = read_u16(pkt + pos);
        u16 qclass = read_u16(pkt + pos + 2);
        if (i == 0 && unlikely(qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN))
            return -1;
        pos += 4;
        if (unlikely(pos > pkt_len)) return -1;
    }

    // Extract answers
    int count = 0;
    if (cname_out && cname_buf_len > 0) cname_out[0] = '\0';

    for (int i = 0; i < ancount; i++) {
        int owner_len = decode_name(pkt, pkt_len, pos, owner, sizeof(owner));
        if (unlikely(owner_len < 0)) return -1;
        pos += (u32)owner_len;

        if (unlikely(pos + 10 > pkt_len)) return -1;

        u16 type   = read_u16(pkt + pos);
        u16 class_ = read_u16(pkt + pos + 2);
        u16 rdlen  = read_u16(pkt + pos + 8);
        pos += 10;

        if (unlikely(pos + rdlen > pkt_len)) return -1;

        if (class_ == DNS_CLASS_IN && name_eq(owner, expected_name)) {
            if (type == DNS_TYPE_CNAME) {
                int cname_len = decode_name(pkt, pkt_len, pos,
                                            cname_target, sizeof(cname_target));
                if (unlikely(cname_len < 0 || (u16)cname_len != rdlen))
                    return -1;
                if (cname_out && cname_buf_len > 0 && cname_out[0] == '\0') {
                    if (unlikely(name_copy(cname_out, cname_buf_len, cname_target) < 0))
                        return -1;
                }
                expected_name = cname_target;
            } else if (type == DNS_TYPE_A && rdlen == 4 && count < max_addrs) {
                u32 addr;
                __builtin_memcpy(&addr, pkt + pos, sizeof(addr));
                addrs[count++] = addr;
            }
        }
        pos += rdlen;
    }

    return count;
}

// --- Public parse API ---

int dns_parse_response(const u8 *pkt, u32 pkt_len, u16 expected_txn_id,
                       u32 *addrs, int max_addrs) {
    return parse_answers(pkt, pkt_len, expected_txn_id,
                         addrs, max_addrs, NULL, 0);
}

int dns_parse_response_cname(const u8 *pkt, u32 pkt_len, u16 expected_txn_id,
                             u32 *addrs, int max_addrs,
                             char *cname_out, u32 cname_buf_len) {
    return parse_answers(pkt, pkt_len, expected_txn_id,
                         addrs, max_addrs, cname_out, cname_buf_len);
}

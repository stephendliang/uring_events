# io_uring Embedded Storage Engine

An LSM-tree storage engine built directly on the reactor core. O_DIRECT WAL, io_uring-native compaction, zero-copy reads from mmap or provided buffer rings. The goal: beat RocksDB on write throughput and tail latency by removing every layer between the application and the NVMe.

## Why RocksDB is slow

RocksDB is brilliant engineering constrained by its I/O model. The bottlenecks:

**1. POSIX I/O abstraction (Env/FileSystem)**

Every read and write goes through a virtual dispatch (`Env::NewWritableFile`, `RandomAccessFile::Read`). This exists for portability (Windows, HDFS, in-memory) but adds vtable indirection in the hottest paths. The default `PosixEnv` does synchronous `pwrite()` + `fdatasync()` — one syscall per WAL write, one per sync. RocksDB's `io_uring` support (`MultiRead`) only covers point lookups in SST files, not writes, not compaction I/O.

**2. WAL is synchronous and single-threaded**

`DBImpl::WriteImpl` takes a mutex, groups writers into a batch, does `pwrite()` to the WAL, then `fdatasync()`. The leader writer does the sync and wakes all followers. The mutex + condvar wakeup chain adds 2-5us per commit even when the group is pre-formed. The fdatasync itself is ~2ms (O_DIRECT) or ~6ms (buffered, from our benchmarks). During that 2-6ms sync window, all writers are blocked — no I/O is being submitted.

**3. Compaction competes with foreground I/O**

Compaction threads do buffered sequential reads and writes. These compete for NVMe bandwidth, page cache, and CPU with foreground point lookups. RocksDB uses `rate_limiter` to throttle compaction, but this is a crude mechanism — it doesn't know about the foreground latency impact in real time. Write stalls from L0→L1 compaction backlog are the single most common RocksDB production issue.

**4. MemTable overhead**

The default SkipList MemTable does `malloc()` per entry. Each insert traverses O(log n) random pointers. At high insert rates, this generates significant allocator pressure and cache misses. The alternative (vector rep, hash rep) have their own problems. All MemTables copy the key-value pair on insert — no zero-copy path.

**5. Block cache inefficiency**

The LRU block cache uses a global mutex (sharded, but still contended at high QPS). Each lookup does: shard selection → mutex lock → hash probe → LRU promotion → mutex unlock → decompress block → binary search within block. That's 6+ operations for a single point read. Cache misses go to `pread()` which is a synchronous syscall.

**6. Compression on the critical path**

SST blocks are compressed (LZ4/Snappy/zstd). Decompression happens synchronously on every cache miss, adding 1-10us depending on block size. This is CPU time spent holding the block cache entry, blocking other readers of the same block.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Client API                            │
│  put(key, val) · get(key) · delete(key) · scan(start,end) │
└────────┬──────────────────────────────────┬────────────────┘
         │ writes                           │ reads
┌────────▼────────────┐         ┌───────────▼──────────────┐
│     Write Path      │         │      Read Path           │
│                     │         │                          │
│  ┌───────────────┐  │         │  MemTable (active+imm)   │
│  │  Ring Buffer   │  │         │         ↓ miss           │
│  │  (WAL in RAM) │  │         │  L0 files (direct read)  │
│  └──────┬────────┘  │         │         ↓ miss           │
│         │ batch     │         │  L1..Ln (io_uring read)  │
│  ┌──────▼────────┐  │         │         ↓                │
│  │  WAL fdatasync │  │         │  Block cache (userspace) │
│  │  (O_DIRECT)   │  │         └──────────────────────────┘
│  └──────┬────────┘  │
│         │           │         ┌──────────────────────────┐
│  ┌──────▼────────┐  │         │   Compaction Engine      │
│  │  MemTable     │  │         │   (io_uring pipeline)    │
│  │  (arena alloc)│  │         │   L0→L1→...→Ln           │
│  └───────────────┘  │         └──────────────────────────┘
└─────────────────────┘
```

### Core principle: the io_uring ring is the I/O scheduler

Every disk I/O in the system — WAL writes, WAL syncs, SST reads, SST writes, compaction reads, compaction writes — goes through a single io_uring ring (per core). The ring provides natural batching, prioritization (via SQE link chains and ordering), and completion-driven scheduling. No thread pools for I/O. No synchronous syscalls in steady state.

## Write Path

### WAL: O_DIRECT group commit via io_uring

The existing bench_wal.c already proves the core design. From the oltp-sweep data:

- O_DIRECT fdatasync p50: **1.94ms** (one NVMe flush)
- Buffered fdatasync p50: **6.0ms** (NVMe flush + XFS journal)
- O_DIRECT group commit gs=4: **1974 txns/sec** (single thread)

The production WAL extends this:

```c
struct wal_writer {
    int fd;                         // O_DIRECT, preallocated
    u64 write_offset;               // current append position
    u8 *ring_buf;                   // mmap'd circular buffer, 64KB
    u32 ring_head, ring_tail;       // producer/consumer cursors
    u32 pending_sync;               // bytes written since last sync
    u64 sequence;                   // monotonic LSN
};
```

**Write flow:**
1. `put()` serializes key+value into the ring buffer (length-prefixed, CRC32C checksum). No malloc. The ring buffer is the WAL's in-memory representation.
2. When the ring buffer accumulates enough data (or a sync is requested), submit one `IORING_OP_WRITE` (O_DIRECT, DMA straight from the ring buffer to NVMe) followed by a linked `IORING_OP_FSYNC`.
3. While the write+sync is in flight, new puts continue filling the ring buffer. The next batch starts forming immediately — no blocking.
4. When the fsync CQE arrives, everything up to that LSN is durable. Notify waiting clients.

**Key difference from RocksDB:** no mutex, no condvar, no leader/follower election. The ring buffer is a lock-free SPSC queue (single producer = the write path, single consumer = the io_uring submission). Group commit happens naturally — all writes that land in the ring buffer before the next submission become one batch.

**Alignment:** O_DIRECT requires 512-byte alignment. The ring buffer base is page-aligned. Each write is padded to 512-byte boundary. Wasted space per write: avg 256 bytes. At 100-byte average KV pairs, this is 3.5x amplification — acceptable for the 3x fdatasync speedup. For large values, the padding overhead becomes negligible.

### MemTable: arena-allocated sorted structure

```c
struct memtable {
    u8 *arena;                  // mmap'd, 64MB, MAP_POPULATE
    u32 arena_offset;           // bump allocator (never frees)
    u32 count;                  // number of entries
    struct mt_entry *index;     // sorted array of pointers into arena
    u64 min_seq, max_seq;       // sequence range
    u64 data_size;              // total key+value bytes
};

struct mt_entry {
    u32 key_offset;             // offset into arena
    u16 key_len;
    u16 val_len;                // 0 = tombstone (delete)
    u64 sequence;
};
```

**Why not a skip list:** Skip lists have O(log n) random pointer chases per insert. At 1M entries, that's ~20 cache misses per insert. A sorted array with binary search has the same O(log n) lookup but better cache locality because the index is contiguous. Inserts are O(n) if you maintain sorted order inline, but we don't — we append unsorted and sort once at flush time (like LevelDB's original design, but without the per-entry malloc).

**Why not a B-tree:** At MemTable scale (64MB, ~500K-1M entries), the overhead of tree node management isn't worth it. The arena + sorted index is simpler, faster to iterate for flush, and has zero fragmentation.

**Immutable MemTable:** when the active MemTable hits 64MB, it becomes immutable and a new one is allocated. The immutable MemTable is scheduled for flush to L0. At most 2 immutable MemTables can exist before writes stall (backpressure).

## Read Path

### Point lookup

```
1. Check active MemTable (binary search on sorted prefix + linear scan on unsorted tail)
2. Check immutable MemTable(s) (binary search, fully sorted)
3. Check L0 files (overlapping key ranges — must check all)
4. Check L1..Ln (non-overlapping — binary search on file boundaries, then one file)
```

For steps 3-4, each SST file read is an `IORING_OP_READ` (O_DIRECT). The index block of each SST is cached in a userspace block cache (see below). A point lookup that misses MemTable does:

1. Read index block from cache → find data block offset
2. Submit `IORING_OP_READ` for the data block
3. On CQE completion, binary search within the data block

**Pipelining:** if the key might be in multiple L0 files, submit all reads in parallel (one SQE per candidate file). First CQE with a match wins; cancel the rest via `IORING_OP_ASYNC_CANCEL`. This turns L0 worst-case from sequential to parallel — bounded by single NVMe latency, not N * NVMe latency.

### Block cache

```c
struct block_cache {
    struct cache_entry *table;      // open-addressing hash table
    u32 capacity;                   // number of slots (power of 2)
    u32 count;                      // occupied slots
    u8 *data_arena;                 // mmap'd, holds decompressed blocks
    u32 arena_head;                 // circular allocator
    u64 clock_hand;                 // CLOCK eviction sweep position
};

struct cache_entry {
    u64 file_id;                    // SST file number
    u64 block_offset;               // offset within file
    u32 data_offset;                // offset into data_arena
    u32 data_len;                   // decompressed size
    u8  ref_bit;                    // CLOCK reference bit
    u8  _pad[7];
};
```

**CLOCK eviction** instead of LRU: no linked list, no mutex. The clock hand sweeps the hash table linearly. Entries with ref_bit=1 get cleared to 0 and skipped. Entries with ref_bit=0 get evicted. A read hit sets ref_bit=1 (single byte write, no locking). This is the same algorithm PostgreSQL uses for its buffer pool — proven at scale, trivially simple.

**No per-shard mutex.** The hash table is accessed by a single thread (shared-nothing architecture). No locks needed. In multicore mode, each worker has its own block cache — same shared-nothing principle as the existing reactor.

## SST File Format

```
┌──────────────────────────────────────┐
│ Data Block 0  (4KB, compressed)      │  ← sorted KV pairs
│ Data Block 1                         │
│ ...                                  │
│ Data Block N                         │
├──────────────────────────────────────┤
│ Index Block   (offsets + last keys)  │  ← one entry per data block
├──────────────────────────────────────┤
│ Bloom Filter  (per-file, FP ~1%)    │  ← avoid unnecessary data reads
├──────────────────────────────────────┤
│ Footer        (32 bytes)             │  ← index offset, bloom offset, magic
└──────────────────────────────────────┘
```

**Data blocks:** 4KB aligned (matches NVMe sector and O_DIRECT alignment). Each block is independently compressed (LZ4 only — fast decompression, no zstd/snappy complexity). Keys are prefix-compressed within each block (common prefix stored once, suffixes delta-encoded).

**Bloom filter:** 10 bits per key, 3 hash functions (~1% false positive rate). Checked before any data block read. Eliminates most negative lookups.

**No restart points, no block handles indirection.** RocksDB's SST format has multiple levels of indirection (block handles, restart arrays, compression dictionaries). Each layer adds decode overhead. This format is simpler: index block maps directly to 4KB-aligned file offsets.

## Compaction Engine

### io_uring-pipelined merge

Compaction is a merge-sort of SST files. RocksDB does this with synchronous reads and writes in a dedicated thread pool. The io_uring approach:

```
Read pipeline          Merge           Write pipeline
─────────────          ─────           ──────────────
SQE: read block A[0]
SQE: read block B[0]
                      ← CQE A[0]  →  merge A[0]+B[0]
SQE: read block A[1]                   → SQE: write C[0]
                      ← CQE B[0]
SQE: read block B[1]
                      ← CQE A[1]  →  merge A[1]+B[1]
                                       → SQE: write C[1]
```

Reads are pipelined 2-4 blocks ahead. While the CPU merges block N, blocks N+1 and N+2 are already in flight. Writes are submitted as soon as a merged block is ready. Everything goes through the same ring as foreground I/O.

**Compaction priority:** foreground reads get higher effective priority because they complete faster (single block) and their CQEs are processed first in the drain loop. Compaction reads are larger and slower. This is natural I/O scheduling without any explicit priority mechanism — the ring's FIFO ordering + NVMe's internal scheduling handles it.

**Rate limiting:** instead of RocksDB's token-bucket rate limiter, use SQE flow control. Limit the number of in-flight compaction SQEs (e.g., max 8 compaction reads + 8 compaction writes). Foreground I/O is unlimited. This provides natural backpressure — if the NVMe is saturated, compaction SQEs wait in the SQ while foreground SQEs are submitted first.

### Leveled compaction (L0 → L1 → ... → Ln)

Same level structure as RocksDB/LevelDB:

| Level | Max size | File size | Key ranges |
|-------|----------|-----------|------------|
| L0 | 64MB (4 files) | 16MB | Overlapping |
| L1 | 256MB | 16MB | Non-overlapping |
| L2 | 2.5GB | 16MB | Non-overlapping |
| L3 | 25GB | 16MB | Non-overlapping |
| L4 | 250GB | 64MB | Non-overlapping |

L0 is special: files have overlapping key ranges (each is a flushed MemTable). L0→L1 compaction must merge all overlapping L0 files with the overlapping range in L1. This is the bottleneck that causes write stalls.

**Mitigation:** start L0→L1 compaction early (at 2 files, not 4) and pipeline it with the foreground write path. The io_uring ring naturally interleaves compaction I/O with WAL writes and foreground reads without explicit scheduling.

### Tombstone compaction

Deletes write a tombstone (key with empty value + delete flag). Tombstones propagate down through compaction. A tombstone can be dropped when it reaches the bottom level (no older version exists below). Tombstone-only compaction: if a level has >50% tombstones by count, compact even if the level isn't full.

## Concurrency Model

**Single-writer, single-reader per core.** The shared-nothing multicore model from the reactor applies directly:

```
Core 0                     Core 1                     Core 2
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ io_uring ring    │      │ io_uring ring    │      │ io_uring ring    │
│ WAL fd           │      │ WAL fd           │      │ WAL fd           │
│ MemTable         │      │ MemTable         │      │ MemTable         │
│ Block cache      │      │ Block cache      │      │ Block cache      │
│ SST file handles │      │ SST file handles │      │ SST file handles │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                         │                         │
         └────── shared SST files on disk (read-only) ──────┘
```

Each core owns its own WAL and MemTable. SST files on disk are shared (read-only after creation, deleted after compaction replaces them). No cross-core coordination for reads or writes. Compaction can be core-local (each core compacts its own L0) or delegated to a compaction core.

**Problem: how do cross-core queries work?** If key K was written on core 0, a get(K) on core 1 won't find it in core 1's MemTable. Options:

1. **Key-range sharding**: each core owns a key range. Routes at the API layer. Simple, deterministic, no cross-core reads. But hot keys all hit one core.
2. **Eventual consistency**: cores flush to shared SST files. Once flushed, all cores can read it. Recent writes (in MemTable) are only visible on the writing core. Acceptable for many workloads.
3. **MSG_RING for cross-core reads**: use `IORING_OP_MSG_RING` to forward a read request to the owning core. Adds one ring-to-ring hop (~100ns) but maintains strict consistency.

**Recommended: option 1 (key-range sharding) for phase 1.** Simplest, no cross-core communication, consistent behavior. Partition keys by hash(key) % num_cores.

## What makes this faster than RocksDB

| Dimension | RocksDB | This |
|-----------|---------|------|
| WAL sync | `pwrite()` + `fdatasync()` (2 syscalls) | Linked WRITE+FSYNC SQEs (0 syscalls in steady state) |
| WAL latency | ~6ms buffered, ~2ms direct | ~2ms (always O_DIRECT) |
| Group commit | Mutex + condvar wakeup chain | Lock-free ring buffer, natural batching |
| MemTable insert | Skip list, malloc per entry | Arena bump allocator, zero malloc |
| Point read I/O | `pread()` sync, one per file | `IORING_OP_READ` batched, parallel L0 probe |
| Compaction I/O | Thread pool, sync read/write | io_uring pipeline, zero syscalls per block |
| Block cache | Sharded LRU, mutex per shard | CLOCK, no mutex (single-thread per core) |
| Concurrency | Global mutex on write path | Shared-nothing, zero locks |
| Binary size | ~20MB (static link) | Target <200KB |
| Dependencies | gflags, snappy, lz4, zstd, jemalloc | nolibc, LZ4 (embedded) |

## Realistic scope

**Phase 1 — WAL + MemTable + flush to L0**
- Extend bench_wal.c into a real WAL (ring buffer, CRC32C, LSN tracking)
- Arena-allocated MemTable with sorted index
- Flush MemTable to SST file (sorted, 4KB-aligned blocks, no compression)
- Point lookup: MemTable → L0 files (sequential scan)
- Bloom filters on L0 files
- API: `put(key, val)`, `get(key)`, `delete(key)`
- No compaction yet — L0 grows unbounded (must restart to reclaim)

**Phase 2 — Compaction + leveled storage**
- L0→L1 compaction (merge-sort, io_uring pipelined)
- L1→L2→...→Ln compaction with size targets
- Index blocks + block cache (CLOCK eviction)
- SST file metadata management (MANIFEST equivalent)
- LZ4 block compression

**Phase 3 — Multicore**
- Key-range sharding across cores
- Per-core WAL + MemTable + block cache
- Shared SST files (read-only, atomic rename on compaction)
- Compaction scheduling (dedicated core or round-robin)

**Phase 4 — Production features**
- Snapshots (MVCC via sequence numbers — already in the design)
- Range scans / iterators (merge iterator across MemTable + all levels)
- Prefix seek optimization (bloom filter on key prefix)
- Backup / checkpoint (hardlink SST files)
- Recovery (WAL replay on startup)
- Column families (or: separate LSM trees sharing the ring)

## Open questions

- **Value size limit**: inline values in data blocks up to what size? Large values (>4KB) should be stored in separate blob files (like RocksDB's BlobDB) to avoid write amplification during compaction.
- **Compression**: LZ4 only, or add zstd for cold levels? zstd is ~100KB of code but 2-3x better ratio on compressible data. Could be worth it for L3+.
- **Write buffer manager**: global memory budget across all MemTables and block caches. RocksDB's WriteBufferManager is complex but necessary to prevent OOM. With fixed mmap arenas this is simpler — just cap the number of arenas.
- **Direct I/O for reads**: O_DIRECT reads bypass the page cache, which means the block cache must be large enough to hold the working set. If the working set exceeds block cache size, every read hits NVMe. For read-heavy workloads with large working sets, buffered reads + page cache might win. Make this configurable per level?
- **WAL recycling**: preallocate WAL files and reuse them (rename + fallocate) instead of create + delete. Avoids filesystem metadata overhead. RocksDB does this (`recycle_log_file_num`).
- **Merge operator**: RocksDB's merge operator enables read-modify-write without a read. Counters, append-to-list, etc. Useful but adds complexity to the merge path. Defer to post-phase-4.

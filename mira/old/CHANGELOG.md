# Changelog - DPDK PCAP Sender

## [2.0] - 2025-01-29

### Fixed
- **Critical bug:** Program hanging for 2-5 minutes (or indefinitely) when pressing Ctrl+C
- **Root cause:** Refcount corruption in mbuf reuse loop causing memory leaks
- **Impact:** Exit time reduced from 120-300s to < 2s (60-150× faster)

### Changed
- **Send loop (lines 197-235):** Replaced manual refcount management with `rte_pktmbuf_clone()`
  - Original approach: Increment refcnt before TX, decrement for unsent packets
  - New approach: Clone mbufs for each burst, TX auto-frees clones
  - Result: No refcount leaks, original mbufs always have refcnt=1

- **Cleanup process (lines 333-381):** Implemented robust mbuf freeing with timeout
  - Added force-free logic for mbufs with refcnt > 1
  - Added 5-second timeout to prevent infinite hangs
  - Added progress indicators every 500K mbufs
  - Removed unnecessary sleeps (was adding ~15s overhead)

- **Signal handler (lines 44-53):** Improved user feedback
  - Added clear "[SIGNAL]" message on Ctrl+C
  - Added stdout flush to ensure message appears immediately

### Performance
- **Throughput:** No change (still 7 Gbps sustained) ✅
- **Exit time:** Reduced from 120-300s to < 2s ✅
- **Overhead:** Clone operation adds ~1.3% CPU overhead (negligible)

### Testing
Tested on CloudLab with:
- 1.5M pre-loaded packets
- 7 Gbps sustained transmission
- Multiple Ctrl+C tests after 10s, 60s, and 300s runs
- All exits completed in < 2 seconds

---

## [1.0] - 2025-01-26

### Added
- Initial DPDK PCAP sender implementation
- Pre-loaded mbuf approach (zero-copy after initial load)
- Rate limiting to 7 Gbps (TARGET_GBPS configurable)
- Support for 1.5M packet PCAPs
- Real-time statistics every 5 seconds

### Known Issues (fixed in v2.0)
- ❌ Program hangs on Ctrl+C after running for several minutes
- ❌ Refcount leaks cause cleanup to take 2-5 minutes
- ❌ No timeout protection during cleanup

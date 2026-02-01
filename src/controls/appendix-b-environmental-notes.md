# APPENDIX B: ENVIRONMENTAL NOTES

**For Your Aerospace/Telemetry Environment:**

Given your experience with high-performance data collection systems (IRIG 106, RTPS UDP, 10 Gbps throughput), these additional considerations apply:

1. **GPU-Accelerated Packet Processing:** If using GPUs for real-time telemetry decoding:
   - MIG may introduce unacceptable latency (2-5%)
   - Consider physical GPU isolation instead
   - Use compute-exclusive mode without MIG for deterministic performance

2. **RDMA Considerations:**
   - GPUDirect RDMA critical for telemetry processing
   - Network encryption (SC-8) may conflict with zero-copy transfers
   - Recommend: Physical network isolation over encryption for GPU fabric

3. **Real-Time Workloads:**
   - Audit logging overhead (1-2%) may impact deterministic processing
   - Consider batch log forwarding vs real-time
   - DCGM polling intervals should be >5s for RT workloads

4. **S3 Upload Integration:**
   - GPU-accelerated compression for telemetry before upload
   - Ensure SC-28 controls don't double-encrypt (S3 SSE + GPU encryption)

**Recommended Aerospace-Specific Profile:**
- Enable: CM-7 (least functionality), SI-7 (integrity), AC-3 (physical isolation)
- Conditional: SC-8 (encrypt management only, not data plane)
- Minimize: AU-2 overhead (batch logging for RT paths)

**Estimated Impact for RT Telemetry:** 3-5% (vs 12-18% general case)

---

**Document Control:**  
Next Review: February 28, 2026  
Owner: Information Security Architecture  
Classification: Internal Use

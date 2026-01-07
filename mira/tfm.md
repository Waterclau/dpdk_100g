# Master's Thesis Proposal

## Title

**MIRA: High-Performance DDoS Detection System Using DPDK and OctoSketch with Embedded Machine Learning**

---

## Proposal Summary

This thesis presents MIRA, a novel high-performance Distributed Denial of Service (DDoS) detection system designed for line-rate network traffic analysis. The system leverages DPDK (Data Plane Development Kit) for zero-copy packet processing and OctoSketch, a memory-efficient probabilistic data structure, to achieve real-time flow tracking at multi-gigabit speeds. MIRA operates as a multi-threaded packet processor with 14 worker cores handling per-flow statistics and a coordinator core performing global aggregation and attack detection. The system achieves 17.6 Gbps throughput with median detection latency of 34ms and zero packet drops, demonstrating the viability of in-line DDoS detection at scale. To address the high false positive rates inherent in threshold-based detection, we extend MIRA with an embedded machine learning classifier (LightGBM) that provides multi-class attack classification while maintaining sub-40ms latency. This hybrid approach combines the speed of threshold-based detection with the accuracy of machine learning, achieving 23× lower latency compared to pure ML-based systems (MULTI-LF: 866ms) while targeting >95% classification accuracy. The proposed system demonstrates that intelligent DDoS defense can be deployed directly in the data plane without sacrificing performance, making it suitable for deployment in high-speed network environments such as ISP edge routers, enterprise gateways, and cloud infrastructure protection points.

---

## Keywords

DDoS Detection, DPDK, OctoSketch, Machine Learning, LightGBM, Real-time Processing, Network Security, High-Performance Computing

---

## Thesis Objectives

1. Design and implement a high-performance DDoS detector using DPDK for line-rate packet processing
2. Integrate OctoSketch probabilistic data structure for memory-efficient flow tracking
3. Develop a hybrid detection mechanism combining threshold-based rules with machine learning classification
4. Embed LightGBM ML model in the data plane for real-time attack classification
5. Evaluate system performance under realistic traffic conditions (benign and attack scenarios)
6. Compare results against state-of-the-art DDoS detection systems
7. Demonstrate sub-50ms detection latency while maintaining >95% accuracy

---

## Expected Contributions

- A novel architecture for embedding ML inference in high-speed DPDK-based network applications
- Experimental validation demonstrating 23× latency reduction compared to external ML approaches
- Comprehensive dataset generation methodology for DDoS detection ML training
- Open-source implementation of MIRA detector for research and educational purposes
- Performance benchmarks showing feasibility of intelligent in-line DDoS defense at 10+ Gbps

---

**Student:** [Your Name]
**Advisor:** [Advisor Name]
**Institution:** [University Name]
**Program:** Master's in [Program Name]
**Academic Year:** 2024-2025
**Status:** Implementation and Evaluation Phase

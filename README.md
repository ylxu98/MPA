MPA: Lightweight and Updatable Integrity Auditing for Decentralized Storage Using Merkle Trees and Polynomial Commitments

This repository contains the core Python implementation of the MPA scheme, tailored for decentralized multi-copy storage environments. The system provides a secure and verifiable mechanism for data owners to audit outsourced data without downloading the entire dataset.

The architecture integrates KZG polynomial commitments and a dynamic rank-based Merkle tree. By utilizing KZG commitments, the protocol achieves constant-size auditing proofs and constant-time verification overhead on the auditor side. The dynamic rank-based Merkle tree structure ensures that data update operations can be processed efficiently with logarithmic complexity.

Extensive benchmark testing has been conducted to evaluate the computational and communication overhead. The experimental results demonstrate the theoretical constant-time verification advantage. Specifically, verifying a data scale of 5000 blocks requires only about 0.041 seconds, and this verification time remains completely stable regardless of the data size growth.

To reproduce the experimental results, researchers can run the comprehensive benchmark script. This script automatically simulates the entire protocol lifecycle, including setup, proof generation, verification, and dynamic updates, outputting the exact time consumption and communication costs.

This open-source implementation serves as the experimental foundation for our research. 

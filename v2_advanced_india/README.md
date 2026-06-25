# Guard Grid V2: Advanced India Implementation

This document outlines the evolution of the Guard Grid project from a theoretical cryptographic model into a robust, fault-tolerant simulation tailored for the Indian smart grid ecosystem.

## Problem Statement
After analyzing the original Guard Grid research paper, we identified several practical limitations preventing its real-world deployment:
* **Fragility to Offline Meters:** The original MIFE (Multi-Input Functional Encryption) scheme crashes if even a single smart meter fails to send its data. The Aggregation Gateway cannot process an incomplete dataset.
* **Lack of Temporal Dynamics:** The theoretical model evaluates single, isolated data points. Real power grids operate continuously over time-series intervals (e.g., 96 slots of 15 minutes per day).
* **Missing Utility Features:** The research focuses entirely on encryption overhead. It lacks essential utility functions like billing, anomaly detection (power theft), and reputation tracking for intermediate nodes.

## Our Proposed Solution
To bridge the gap between cryptographic theory and practical deployment, V2 introduces a functional wrapper architecture around the core MIFE scheme:
* **Dummy Ciphertext Injection:** A fault-tolerance mechanism where the Aggregation Gateway substitutes missing meter data with pre-generated "dummy ciphertexts". These decrypt to zero, allowing the aggregation equation to complete successfully while the Control Center dynamically adjusts the master session key.
* **Time-Series Pipeline:** A continuous processing loop simulating a full 24-hour cycle, buffering and aggregating encrypted data at standard 15-minute intervals.
* **Statistical Anomaly Detection:** A rolling z-score layer on the Control Center to monitor decrypted neighborhood aggregates for sudden spikes or drops, flagging potential anomalies without exposing individual houses.

### Example: Fault Tolerance in Practice
To perfectly illustrate our solution to the "Fragility to Offline Meters" problem, consider a 3-meter scenario where **SM1** suddenly loses connection:
1. **The Problem:** The Aggregation Gateway (AG) receives ciphertexts from SM2 and SM3, but its MIFE aggregation buffer is incomplete. Under the original protocol, the system would immediately crash.
2. **The Substitution:** The AG detects the missing ciphertext, pulls a pre-generated Dummy Ciphertext from the TTP, and substitutes it into SM1's slot.
3. **The Decryption:** The dummy ciphertext decrypts to exactly 0 kW. Knowing SM1 was offline, the Control Center dynamically adjusts the master decryption mask ($K$) by safely dropping SM1's session key ($k_1$).
4. **The Outcome:** The network successfully decrypts the remaining aggregate (e.g., 5.749 kW from SM2 and SM3) without ever exposing their individual readings. The billing and aggregation pipeline continues functioning without interruption.

## Goal
To prove that privacy-preserving functional encryption can be deployed in a volatile, high-latency smart grid environment without sacrificing system stability or necessary utility operations like revenue calculation.

## Benefits for the Indian Scenario
India's Revamped Distribution Sector Scheme (RDSS) aims to install 250 million smart meters. V2 is designed with this ecosystem in mind:
* **DERC Tariff Integration:** Calculates estimated feeder-level revenue using the official progressive 3-slab domestic tariff (Delhi region).
* **High-Latency Resilience:** Indian telecom networks can face intermittent drops. The fault-tolerance module ensures the grid's aggregation pipeline doesn't freeze when meters temporarily lose connection.
* **Privacy by Design:** Aligns closely with the new Digital Personal Data Protection Act (DPDP) by ensuring the local Gateway never sees raw household consumption.

## Technical Concepts & Methods Used
* **MIFE (Multi-Input Functional Encryption):** Core cryptographic concept that allows computation (summation) over encrypted values without decrypting the underlying data.
* **DH (Diffie-Hellman) Key Agreement:** Used to create shared session masks between the edge meters and the central Control Center.
* **LHH (Linear Homomorphic Hashing):** Used by the Control Center to cryptographically verify that the gateway aggregated the data honestly.
* **Threshold Substitution:** Our custom method for handling missing ciphertexts by dynamically patching the MIFE aggregation buffer and realigning the decryption mask on the fly.

## Algorithms
1. **Setup (TTP):** Generates 512-bit safe primes, DH parameters, and MIFE functional keys.
2. **Key Agreement (SM & CC):** Computes shared session keys ($k_i$) via Diffie-Hellman exchange.
3. **Masking & Encryption (SM):** Meters mask their real reading with $k_i$ before applying MIFE encryption.
4. **Fault-Tolerant Aggregation (AG):** Replaces offline meter ciphertexts with zero-value dummies, then aggregates via MIFE inner product.
5. **Verification & Decryption (CC):** Verifies the aggregate using LHH, subtracts the dynamically adjusted session key mask, and recovers the true neighborhood total.

## Future Advancements
* **Dynamic Pricing (ToU):** Integrating real-time Time-of-Use pricing where the Control Center adjusts the tariff dynamically based on the decrypted aggregate load.
* **Hardware Acceleration:** Offloading the heavy MIFE pairing operations to dedicated FPGA/ASIC chips inside the physical smart meters.
* **Decentralized TTP:** Replacing the single Trusted Third Party with a distributed blockchain oracle to eliminate the single point of failure during the initial setup phase.

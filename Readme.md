# Private GOC Ledger

> A privacy-preserving CRDT-based distributed ledger using homomorphic encryption and non-interactive zero-knowledge proofs.

This project is a prototype implementation of a **Private GOC Ledger**, developed as part of my Bachelor's thesis at the University of Basel.

The goal is to combine the scalability and eventual consistency of a **CRDT-based ledger** with modern cryptographic techniques so that transaction correctness can be verified **without revealing transaction values**.

---

## Motivation

Traditional distributed ledgers typically require global consensus to maintain consistency.

The original **GOC Ledger** demonstrates that ledgers can instead be implemented as **Conflict-Free Replicated Data Types (CRDTs)**, allowing replicas to merge independently without consensus.

However, the original design stores all transaction information in plaintext.

This project extends that model by introducing:

- encrypted transaction values
- additive ElGamal encryption
- non-interactive zero-knowledge proofs
- privacy-preserving verification of transaction consistency

The result is a ledger where replicas can merge encrypted state while verifying correctness without decrypting transaction amounts.

---

## Features

- CRDT-inspired ledger structure
- Additive (Exponential) ElGamal encryption
- Homomorphic aggregation of encrypted values
- Non-interactive equality Zero-Knowledge Proofs
- Fiat-Shamir transformation
- Java implementation
- Modular cryptographic architecture

---

## How it Works

Instead of storing plaintext balances, the ledger stores encrypted transaction contributions.

Each transaction is encrypted twice:

- once under the sender's public key
- once under the receiver's public key

Every transaction additionally carries a **Zero-Knowledge Proof** showing that both ciphertexts encrypt the **same plaintext value**.

This allows:

- receivers to verify correctness
- replicas to merge encrypted state
- transaction values to remain confidential

---

## Ledger Representation

Rather than storing a single balance between two accounts, each matrix cell contains encrypted transaction data.

```
Sender \ Receiver

        Alice      Bob      Carol

Alice     ∅      {Tx...}   {Tx...}
Bob       ∅        ∅          ∅
Carol     ∅      {Tx...}      ∅
```

State merging is simply performed using **set union**, preserving the monotonic growth required by CRDTs.

---

## Cryptography

The implementation uses:

- **2048-bit MODP Group (RFC 3526 Group 14)**
- Additive (Exponential) ElGamal
- Schnorr Equality-of-Discrete-Logarithms Proof
- Fiat-Shamir heuristic
- SHA-256 challenge generation

The current implementation focuses on demonstrating the cryptographic mechanisms rather than production deployment.

---

## Project Structure

```
Application
    │
    ▼
 Ledger
    │
    ├──────────────► Zero-Knowledge Proofs
    │
    ▼
Cryptographic Engine
    │
    ▼
Crypto Primitives
```

### Main Components

| Component | Responsibility |
|-----------|----------------|
| Ledger | Stores encrypted ledger state |
| Cryptographic Engine | Encryption and group operations |
| Zero-Knowledge Proofs | Proof generation and verification |
| Crypto Primitives | Modular arithmetic and group operations |

---

## Example Transaction Flow

1. Sender encrypts transaction value under both participants' public keys.
2. Sender generates a Zero-Knowledge Proof that both ciphertexts represent the same value.
3. Transaction is submitted.
4. Ledger verifies the proof.
5. If valid, encrypted transaction is accepted.

No participant other than the sender/receiver can recover the transaction amount.

---

## Current Limitations

This repository is a **research prototype**, not a production-ready ledger.

Current limitations include:

- No networking layer
- No replica synchronization implementation
- No CRDT merge protocol implementation
- No transaction history retention
- No range proofs for preventing double spending
- Balance proof interface currently acts as a placeholder

---

## Future Work

Potential extensions include:

- Full CRDT replica synchronization
- History-preserving ledger storage
- Balance-preservation zero-knowledge proofs
- Range proofs for double-spending prevention
- Batched proof verification
- Performance optimizations
- Persistent storage
- Distributed networking

---

## Technologies

- Java
- BigInteger arithmetic
- ElGamal Cryptography
- SHA-256
- Zero-Knowledge Proofs
- Fiat-Shamir Transformation

---

## References

This work builds primarily upon:

- **GOC Ledger: A Conflict-Free Replicated Ledger** (Google Research)
- ElGamal Encryption
- Schnorr Proofs
- Fiat-Shamir Heuristic

See the accompanying Bachelor's thesis for the complete theoretical background and formal design.

---

## Thesis

This repository accompanies the Bachelor's thesis:

**Private GOC Ledger: Consistency Verification Without Decryption**

University of Basel  
Bachelor of Science

---

## Disclaimer

This project was developed for academic research purposes.

It demonstrates how homomorphic encryption and zero-knowledge proofs can be integrated into a CRDT-based ledger architecture, but it is **not intended for production use**.

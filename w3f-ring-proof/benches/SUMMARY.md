# w3f-ring-proof Benchmark Results

Measured with `cargo bench --bench ring_proof -p w3f-ring-proof -- --quick`.

Curve: Bandersnatch on BLS12-381 with KZG. Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 6.18.9, rustc 1.93.0.

## Setup (PCS + PIOP Parameters)

| Domain Size | Time     |
|-------------|----------|
| 512         | 45.8 ms  |
| 1024        | 77.9 ms  |

Includes KZG trusted setup (`3 * domain_size` degree) and domain/PIOP parameter construction.

## Indexing (Fixed Column Commitments)

| Domain Size | Time     |
|-------------|----------|
| 512         | 43.3 ms  |
| 1024        | 79.7 ms  |

Commits the ring key columns and selector polynomial using KZG. Full keyset (max capacity).

## Proving

| Domain Size | Time      |
|-------------|-----------|
| 512         | 158 ms    |
| 1024        | 279 ms    |

Single proof generation. Includes witness generation (conditional additions, inner product accumulation) and PLONK prover (constraint evaluation, quotient polynomial, KZG commitments and openings).

## Single Verification

| Domain Size | Time     |
|-------------|----------|
| 512         | 3.30 ms  |
| 1024        | 3.30 ms  |

Single proof verification. Dominated by pairing checks. Near-constant with domain size as the verifier works with evaluations, not full polynomials.

## Batch Verification (domain_size = 1024)

| Batch Size | Sequential | KZG Accumulator | Speedup |
|------------|------------|-----------------|---------|
| 1          | 3.32 ms    | 3.09 ms         | 1.1x    |
| 4          | 13.4 ms    | 5.54 ms         | 2.4x    |
| 16         | 53.0 ms    | 11.4 ms         | 4.7x    |
| 32         | 106 ms     | 18.6 ms         | 5.7x    |

Sequential verification scales linearly (one pairing check per proof). KZG accumulator batches all pairing equations into a single check via MSM, giving sub-linear scaling.

## Proof Size

| Format     | Size    |
|------------|---------|
| Compressed | 592 bytes |

Serialization time: ~723 ns.

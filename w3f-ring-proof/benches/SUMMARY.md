# w3f-ring-proof Benchmark Results

Measured with `cargo bench --bench ring_proof -p w3f-ring-proof -- --quick`.

Curve: Bandersnatch on BLS12-381 with KZG. Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 6.18.9, rustc 1.93.0.

## Setup (PCS + PIOP Parameters)

| Domain Size | Time     |
|-------------|----------|
| 512         | 49.7 ms  |
| 1024        | 78.1 ms  |

Includes KZG trusted setup (`3 * domain_size` degree) and domain/PIOP parameter construction.

## Indexing (Fixed Column Commitments)

| Domain Size | Time     |
|-------------|----------|
| 512         | 43.3 ms  |
| 1024        | 73.8 ms  |

Commits the ring key columns and selector polynomial using KZG. Full keyset (max capacity).

## Proving

| Domain Size | Time      |
|-------------|-----------|
| 512         | 158 ms    |
| 1024        | 276 ms    |

Single proof generation. Includes witness generation (conditional additions, inner product accumulation) and PLONK prover (constraint evaluation, quotient polynomial, KZG commitments and openings).

## Single Verification

| Domain Size | Time     |
|-------------|----------|
| 512         | 3.21 ms  |
| 1024        | 3.08 ms  |

Single proof verification. Dominated by pairing checks. Near-constant with domain size as the verifier works with evaluations, not full polynomials.

## Batch Verification (domain_size = 1024)

| Batch Size | Sequential | KZG Accumulator | Speedup |
|------------|------------|-----------------|---------|
| 1          | 3.33 ms    | 3.08 ms         | 1.1x    |
| 4          | 13.2 ms    | 5.64 ms         | 2.3x    |
| 16         | 52.8 ms    | 12.0 ms         | 4.4x    |
| 32         | 106 ms     | 19.8 ms         | 5.4x    |

Sequential verification scales linearly (one pairing check per proof). KZG accumulator batches all pairing equations into a single check via MSM, giving sub-linear scaling.

## Proof Size

| Format     | Size    |
|------------|---------|
| Compressed | 592 bytes |

Serialization time: ~770 ns.

# w3f-ring-proof Benchmark Results

Measured with `cargo bench --bench ring_proof -p w3f-ring-proof -- --quick`.

Curve: Bandersnatch on BLS12-381 with KZG. Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 7.2.11, rustc 1.98.1.

## Setup (PCS + PIOP Parameters)

| Domain Size | Time     |
|-------------|----------|
| 512         | 47.1 ms  |
| 1024        | 79.9 ms  |

Includes KZG trusted setup (`3 * domain_size` degree) and domain/PIOP parameter construction.

## Indexing (Fixed Column Commitments)

| Domain Size | Time     |
|-------------|----------|
| 512         | 39.3 ms  |
| 1024        | 66.6 ms  |

Commits the ring key columns and selector polynomial using KZG. Full keyset (max capacity).

## Proving

| Domain Size | Time      |
|-------------|-----------|
| 512         | 132 ms    |
| 1024        | 218 ms    |

Single proof generation. Includes witness generation (conditional additions, inner product accumulation) and PLONK prover (constraint evaluation, quotient polynomial, KZG commitments and openings).

## Single Verification

| Domain Size | Time     |
|-------------|----------|
| 512         | 2.93 ms  |
| 1024        | 3.07 ms  |

Single proof verification. Dominated by pairing checks. Near-constant with domain size as the verifier works with evaluations, not full polynomials.

## Batch Verification (domain_size = 1024)

| Batch Size | Sequential | KZG Accumulator | Speedup |
|------------|------------|-----------------|---------|
| 1          | 3.01 ms    | 2.77 ms         | 1.1x    |
| 4          | 11.8 ms    | 4.98 ms         | 2.4x    |
| 16         | 46.9 ms    | 10.5 ms         | 4.5x    |
| 32         | 92.7 ms    | 17.0 ms         | 5.5x    |

Sequential verification scales linearly (one pairing check per proof). KZG accumulator batches all pairing equations into a single check via MSM, giving sub-linear scaling.

## Proof Size

| Format     | Size    |
|------------|---------|
| Compressed | 592 bytes |

Serialization time: ~710 ns.

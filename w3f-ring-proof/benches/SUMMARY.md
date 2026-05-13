# w3f-ring-proof Benchmark Results

Measured with `cargo bench --bench ring_proof -p w3f-ring-proof -- --quick`.

Curve: Bandersnatch on BLS12-381 with KZG. Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 7.0.5, rustc 1.95.0.

## Setup (PCS + PIOP Parameters)

| Domain Size | Time     |
|-------------|----------|
| 512         | 47.1 ms  |
| 1024        | 92.7 ms  |

Includes KZG trusted setup (`3 * domain_size` degree) and domain/PIOP parameter construction.

## Indexing (Fixed Column Commitments)

| Domain Size | Time     |
|-------------|----------|
| 512         | 44.3 ms  |
| 1024        | 62.8 ms  |

Commits the ring key columns and selector polynomial using KZG. Full keyset (max capacity).

## Proving

| Domain Size | Time      |
|-------------|-----------|
| 512         | 154 ms    |
| 1024        | 244 ms    |

Single proof generation. Includes witness generation (conditional additions, inner product accumulation) and PLONK prover (constraint evaluation, quotient polynomial, KZG commitments and openings).

## Single Verification

| Domain Size | Time     |
|-------------|----------|
| 512         | 3.44 ms  |
| 1024        | 3.37 ms  |

Single proof verification. Dominated by pairing checks. Near-constant with domain size as the verifier works with evaluations, not full polynomials.

## Batch Verification (domain_size = 1024)

| Batch Size | Sequential | KZG Accumulator | Speedup |
|------------|------------|-----------------|---------|
| 1          | 2.90 ms    | 2.72 ms         | 1.1x    |
| 4          | 11.6 ms    | 4.85 ms         | 2.4x    |
| 16         | 47.0 ms    | 9.78 ms         | 4.8x    |
| 32         | 95.2 ms    | 16.1 ms         | 5.9x    |

Sequential verification scales linearly (one pairing check per proof). KZG accumulator batches all pairing equations into a single check via MSM, giving sub-linear scaling.

## Proof Size

| Format     | Size      |
|------------|-----------|
| Compressed | 592 bytes |

Serialization time: ~693 ns.

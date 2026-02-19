# w3f-ring-proof Benchmark Results

Measured with `cargo bench --bench ring_proof -p w3f-ring-proof -- --quick`.

Curve: Bandersnatch on BLS12-381 with KZG. Single-threaded, release profile.

## Setup (PCS + PIOP Parameters)

| Domain Size | Time     |
|-------------|----------|
| 512         | 61.9 ms  |
| 1024        | 86.1 ms  |

Includes KZG trusted setup (`3 * domain_size` degree) and domain/PIOP parameter construction.

## Indexing (Fixed Column Commitments)

| Domain Size | Time     |
|-------------|----------|
| 512         | 48.0 ms  |
| 1024        | 92.0 ms  |

Commits the ring key columns and selector polynomial using KZG. Full keyset (max capacity).

## Proving

| Domain Size | Time      |
|-------------|-----------|
| 512         | 159 ms    |
| 1024        | 289 ms    |

Single proof generation. Includes witness generation (conditional additions, inner product accumulation) and PLONK prover (constraint evaluation, quotient polynomial, KZG commitments and openings).

## Single Verification

| Domain Size | Time     |
|-------------|----------|
| 512         | 3.63 ms  |
| 1024        | 3.36 ms  |

Single proof verification. Dominated by pairing checks. Near-constant with domain size as the verifier works with evaluations, not full polynomials.

## Batch Verification (domain_size = 1024)

| Batch Size | Sequential | KZG Accumulator | Speedup |
|------------|------------|-----------------|---------|
| 1          | 3.10 ms    | 3.10 ms         | 1.0x    |
| 4          | 14.0 ms    | 5.29 ms         | 2.6x    |
| 16         | 49.8 ms    | 11.3 ms         | 4.4x    |
| 32         | 99.6 ms    | 19.8 ms         | 5.0x    |

Sequential verification scales linearly (one pairing check per proof). KZG accumulator batches all pairing equations into a single check via MSM, giving sub-linear scaling.

## Proof Size

| Format     | Size    |
|------------|---------|
| Compressed | 592 bytes |

Serialization time: ~771 ns.

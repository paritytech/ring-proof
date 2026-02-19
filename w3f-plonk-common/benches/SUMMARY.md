# w3f-plonk-common Benchmark Results

Measured with `cargo bench --bench plonk_common -p w3f-plonk-common -- --quick`.

Curve: Bandersnatch (on BLS12-381). Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 6.18.9, rustc 1.93.0.

## Domain Creation

| Domain Size | Hiding    | Non-Hiding |
|-------------|-----------|------------|
| 512         | 889 us    | 891 us     |
| 1024        | 1.92 ms   | 1.88 ms    |
| 4096        | 10.2 ms   | 10.1 ms    |
| 16384       | 47.8 ms   | 48.6 ms    |

Hiding vs non-hiding makes no measurable difference. Scales roughly linearly with domain size.

## Field Column Construction

| Domain Size | private_column | public_column | shifted_4x |
|-------------|----------------|---------------|------------|
| 512         | 452 us         | 446 us        | ~0.25 ns   |
| 1024        | 987 us         | 987 us        | ~0.25 ns   |
| 4096        | 4.44 ms        | 4.76 ms       | ~0.25 ns   |

Column construction is dominated by FFT (interpolation + 4x evaluation). `shifted_4x` returns a cached reference.

## Booleanity Gadget

Constraint evaluation in 4x domain.

| Domain Size | constraints |
|-------------|-------------|
| 512         | 45.7 us     |
| 1024        | 105 us      |
| 4096        | 437 us      |

Single constraint `b(1-b)`. Linear scaling.

## Inner Product Gadget

| Domain Size | init    | constraints | constraints_linearized |
|-------------|---------|-------------|------------------------|
| 512         | 1.30 ms | 102 us      | 10.5 us                |
| 1024        | 3.00 ms | 218 us      | 21.0 us                |
| 4096        | 16.4 ms | 910 us      | 80.5 us                |

Init includes column construction (2 FFTs). Constraints are evaluated pointwise in 4x domain. Linearization is a single polynomial scalar multiplication.

## TE Conditional Addition Gadget

| Domain Size | init     | constraints | constraints_linearized |
|-------------|----------|-------------|------------------------|
| 512         | 2.41 ms  | 913 us      | 80.0 us                |
| 1024        | 5.24 ms  | 1.83 ms     | 168 us                 |
| 4096        | 28.5 ms  | 11.4 ms     | 645 us                 |

Init includes EC conditional additions (batch-normalized) plus column construction. Constraint evaluation is the most expensive gadget due to the degree-4 EC addition formulas. Linearization remains cheap.

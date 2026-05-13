# w3f-plonk-common Benchmark Results

Measured with `cargo bench --bench plonk_common -p w3f-plonk-common -- --quick`.

Curve: Bandersnatch (on BLS12-381). Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 7.0.5, rustc 1.95.0.

## Domain Creation

| Domain Size | Hiding    | Non-Hiding |
|-------------|-----------|------------|
| 512         | 866.71 us | 822.36 us  |
| 1024        | 2.06 ms   | 1.68 ms    |
| 4096        | 7.90 ms   | 7.88 ms    |
| 16384       | 50.2 ms   | 41.6 ms    |

Hiding vs non-hiding makes no measurable difference. Scales roughly linearly with domain size.

## Field Column Construction

| Domain Size | private_column | public_column | shifted_4x |
|-------------|----------------|---------------|------------|
| 512         | 427 us         | 402 us        | 2.12 us    |
| 1024        | 899 us         | 887 us        | 4.42 us    |
| 4096        | 4.33 ms        | 4.18 ms       | 17.9 us    |

Column construction is dominated by FFT (interpolation + 4x evaluation). `shifted_4x` clones and rotates the 4x evaluations.

## Booleanity Gadget

Constraint evaluation in 4x domain.

| Domain Size | constraints |
|-------------|-------------|
| 512         | 42.3 us     |
| 1024        | 85.0 us     |
| 4096        | 384 us      |

Single constraint `b(1-b)`. Linear scaling.

## Inner Product Gadget

| Domain Size | init    | constraints | constraints_linearized |
|-------------|---------|-------------|------------------------|
| 512         | 1.23 ms | 99.9 us     | 9.64 us                |
| 1024        | 2.82 ms | 192 us      | 19.5 us                |
| 4096        | 12.9 ms | 820 us      | 75.9 us                |

Init includes column construction (2 FFTs). Constraints are evaluated pointwise in 4x domain. Linearization is a single polynomial scalar multiplication.

## TE Conditional Addition Gadget

| Domain Size | init     | constraints | constraints_linearized |
|-------------|----------|-------------|------------------------|
| 512         | 2.22 ms  | 829 us      | 75.2 us                |
| 1024        | 4.74 ms  | 1.67 ms     | 158 us                 |
| 4096        | 24.9 ms  | 11.4 ms     | 654 us                 |

Init includes EC conditional additions (batch-normalized) plus column construction. Constraint evaluation is the most expensive gadget due to the degree-4 EC addition formulas. Linearization remains cheap.

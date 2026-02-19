# w3f-plonk-common Benchmark Results

Measured with `cargo bench --bench plonk_common -p w3f-plonk-common -- --quick`.

Curve: Bandersnatch (on BLS12-381). Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 6.18.9, rustc 1.93.0.

## Domain Creation

| Domain Size | Hiding    | Non-Hiding |
|-------------|-----------|------------|
| 512         | 883 us    | 869 us     |
| 1024        | 1.89 ms   | 1.89 ms    |
| 4096        | 9.52 ms   | 9.71 ms    |
| 16384       | 43.3 ms   | 45.3 ms    |

Hiding vs non-hiding makes no measurable difference. Scales roughly linearly with domain size.

## Field Column Construction

| Domain Size | private_column | public_column | shifted_4x |
|-------------|----------------|---------------|------------|
| 512         | 419 us         | 418 us        | 2.14 us    |
| 1024        | 1.02 ms        | 1.14 ms       | 4.29 us    |
| 4096        | 4.45 ms        | 4.92 ms       | 18.7 us    |

Column construction is dominated by FFT (interpolation + 4x evaluation). `shifted_4x` clones and rotates the 4x evaluations.

## Booleanity Gadget

Constraint evaluation in 4x domain.

| Domain Size | constraints |
|-------------|-------------|
| 512         | 48.3 us     |
| 1024        | 96.8 us     |
| 4096        | 412 us      |

Single constraint `b(1-b)`. Linear scaling.

## Inner Product Gadget

| Domain Size | init    | constraints | constraints_linearized |
|-------------|---------|-------------|------------------------|
| 512         | 1.36 ms | 108 us      | 10.2 us                |
| 1024        | 2.98 ms | 223 us      | 20.9 us                |
| 4096        | 14.2 ms | 922 us      | 81.8 us                |

Init includes column construction (2 FFTs). Constraints are evaluated pointwise in 4x domain. Linearization is a single polynomial scalar multiplication.

## TE Conditional Addition Gadget

| Domain Size | init     | constraints | constraints_linearized |
|-------------|----------|-------------|------------------------|
| 512         | 2.39 ms  | 913 us      | 81.1 us                |
| 1024        | 5.20 ms  | 1.83 ms     | 160 us                 |
| 4096        | 25.5 ms  | 11.3 ms     | 642 us                 |

Init includes EC conditional additions (batch-normalized) plus column construction. Constraint evaluation is the most expensive gadget due to the degree-4 EC addition formulas. Linearization remains cheap.

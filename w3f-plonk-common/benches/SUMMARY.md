# w3f-plonk-common Benchmark Results

Measured with `cargo bench --bench plonk_common -p w3f-plonk-common -- --quick`.

Curve: Bandersnatch (on BLS12-381). Single-threaded, release profile.

Machine: AMD Ryzen Threadripper 3970X (64 logical cores), 62 GiB RAM, Arch Linux 6.18.9, rustc 1.93.0.

## Domain Creation

| Domain Size | Hiding    | Non-Hiding |
|-------------|-----------|------------|
| 512         | 884 us    | 865 us     |
| 1024        | 1.90 ms   | 1.89 ms    |
| 4096        | 8.79 ms   | 8.85 ms    |
| 16384       | 44.2 ms   | 44.1 ms    |

Hiding vs non-hiding makes no measurable difference. Scales roughly linearly with domain size.

## Field Column Construction

| Domain Size | private_column | public_column | shifted_4x |
|-------------|----------------|---------------|------------|
| 512         | 455 us         | 445 us        | 2.31 us    |
| 1024        | 982 us         | 981 us        | 4.62 us    |
| 4096        | 4.76 ms        | 4.68 ms       | 22.8 us    |

Column construction is dominated by FFT (interpolation + 4x evaluation). `shifted_4x` is a cheap rotate+copy.

## Booleanity Gadget

Constraint evaluation in 4x domain.

| Domain Size | constraints |
|-------------|-------------|
| 512         | 45.1 us     |
| 1024        | 90.9 us     |
| 4096        | 384 us      |

Single constraint `b(1-b)`. Linear scaling.

## Inner Product Gadget

| Domain Size | init    | constraints | constraints_linearized |
|-------------|---------|-------------|------------------------|
| 512         | 1.65 ms | 100 us      | 9.73 us                |
| 1024        | 3.20 ms | 210 us      | 19.6 us                |
| 4096        | 13.8 ms | 942 us      | 94.2 us                |

Init includes column construction (2 FFTs). Constraints are evaluated pointwise in 4x domain. Linearization is a single polynomial scalar multiplication.

## TE Conditional Addition Gadget

| Domain Size | init     | constraints | constraints_linearized |
|-------------|----------|-------------|------------------------|
| 512         | 3.78 ms  | 857 us      | 75.9 us                |
| 1024        | 8.03 ms  | 1.72 ms     | 162 us                 |
| 4096        | 35.2 ms  | 13.9 ms     | 669 us                 |

Init includes EC conditional additions (sequential scan) plus column construction. Constraint evaluation is the most expensive gadget due to the degree-4 EC addition formulas. Linearization remains cheap.

# Approaches for path coverage analysis/comparison

## BDA: Practical Dependence Analysis for Binary Executables by Unbiased Whole-Program Path Sampling and Per-Path Abstract Interpretation

### Loops: Bound to limit for all loops
E.g. If the bound is 3 and we have an inner loop executing A times and an outer loop B times, then A + B <= 3 is the applied bound for termination of the analysis.
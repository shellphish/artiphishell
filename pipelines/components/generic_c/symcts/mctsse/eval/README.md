# Analyses to do

## Approaches

### Normal fuzzing
    - AFL++
    - AFLFast
    - FairFuzz
    - DigFuzz
    - EcoFuzz
### Hybrid Fuzzing
    - AFL++ + QSym
    - SHFuzz
    - AFL++ + SymCC

## Types of analysis
    - For each branch, how many inputs trigger it (Coverage split)
    - For each branch, how many different bitmaps reach it (Path diversity)

## Targets
| Target name      | Coverage approx. paths well? | Robustness against mutations | 
| :--------------- | :--------------------------: | :--------------------------: |
| linear_ifs       |      :heavy_check_mark:      |       :heavy_check_mark:     |
| linear_ifs_sums  |      :heavy_check_mark:      |             :x:              |
| stacked_ifs      |             :x:              |       :heavy_check_mark:     |
| stacked_ifs_sums |             :x:              |             :x:              |
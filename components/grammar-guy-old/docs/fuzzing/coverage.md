# Coverage

## GCOV General

`gprof` for information such as: How often did xyz run. How

## [GCC Instrumentation](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Optionshtml#Instrumentation-Options)

### Compile Flags

#### `--coverage`

This combines `-fprofile-arcs` and `-ftest-coverage` at time of compilation and `-lgcov` when linking. This basically implies compilation like: 

- **Compilation**:
        `gcc [other flags] -fprofile-arcs -ftest-coverage -c -Wall -Werror main.c`
        `gcc [other flags] -fprofile-arcs -ftest-coverage -c -Wall -Werror other_file.c`

- **Linking**:
            `gcc [other flags] -fprofile-arcs -ftest-coverage -o main main.o other_file.o`

Compilation now generates two additional `auxname.gcno` files

#### `-fprofile-arcs`

Produces a *auxname.gcno* file that can be used by gcov to show program coverage.

#### `-ftest-coverage`

#### Look out for

- Compilation without optimization
- Can parse gcov file into json format using `--json-format`. Yields *.gcov.json.gz* archive containing the compressed files. Consider [this](https://gcc.gnu.org/onlinedocs/gcc/Invoking-Gcov.html)
- 
-  
## LLVM Instrumentation
### Compile Flags

#### `llvm-cov`
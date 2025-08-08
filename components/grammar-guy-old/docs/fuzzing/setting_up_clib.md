# Prepare the build.sh

- remove first lines before "Copyright"
- set environment variables for CC CXX CFLAGS CXXFLAGS OUT SRC WORK etc (as seen below in path)
- the LIB_FUZZING_ENGINE specifies the harness that "we wrote"
- fuzzing executable will appear in $OUT. There you can hand input to the harness. 

TODO: Coverage collection how? 

# Rebuilding the fuzzing harness

- run `github restore -p` to remove all the replaced functions and allow rebuild 
- go to clib parent folder 
- add environment variables
    - `CC=clang CFLAGS=--coverage CXXFLAGS=--coverage CXX=clang++ SRC=$(realpath .) OUT=$(realpath output_files) WORK=$(realpath work_files) LIB_FUZZING_ENGINE=$(realpath test_grammarinator/src/clib_harness.c) ./build.sh`


## Generating Grammar 

- Use in this order, adjust grammar if needed and rebuild if necessary.
    - `grammarinator-process grammars/clib_combined4_gpt4.g4 --rule=clibJson -o generators/`
    - `grammarinator-generate --sys-path generators/ ClibJsonGenerator.ClibJsonGenerator --rule clibJson -d 20 -o generated_inputs/clib/test_%d.html -n 100`
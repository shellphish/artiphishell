# Commandline runners to build targets

- go to work folder. Run: `rm -rf output/coverage/clib/*; ./generate_input.sh clib clibJson clib_simple.g4 1000; cd ../targets; ./collect_coverage.sh 1000 clib; ./generate_coverage_report.sh clib; cd -;`
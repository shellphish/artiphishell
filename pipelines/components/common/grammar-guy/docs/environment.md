
# Environment overview for grammar-guy

## All Env Variables

- **GG_INPUT** 
- **GG_TARGET**
- **GG_COVERAGE**
  - all coverage.profraw files will be in root
  - COVERAGE/functions
- **GG_ROOT**
- **GG_GRAMMARS**
- **GG_BINARY**
- **GG_SCRIPTS**
- **GG_INDEX**
- **GG_JSON_REGISTER**
- **GG_HARNESS_INFO**
## What goes where

- **GG_INPUT** *(/shellphish/generated-inputs/)*:
  - all the gernerated input files
  - the generator folder
- **GG_TARGET**:
  - The target source folder (cp)
  - The oss.crash file
- **GG_COVERAGE** *(/shellphish/coverage)*: 
  - The coverage_collection output (profraw files) per iteration
  - The functions folder containing the split function coverage files per iteration
- **GG_ROOT**: 
  - All the other folders: 
    - coverage
    - input
    - grammars
    - src 
    - allowlist.txt
- **GG_GRAMMARS** *(/shellphish/grammars)*: 
  - the initial grammar (copied in?)
  - spearfuzz.g4
- **GG_BINARY** *(path to binary being run)*:
  - set when paper starts
- **GG_SCRIPTS** *(/shellphish/scripts)*: 
  - The folder containing all the scripts necessary to run the thing 
- **GG_INDEX** *(file that contains function index - passed from outside)*: 
  - The path from somewhere containing the index file for the target
- **GG_JSON_REGISTER** *(path to folder containing files referenced in function index)*: 
  - The path to the register files that are indexed in the GG_INDEX file 
- **GG_BINARY**:
  - The path to the binary as extracted from the index
- **GG_HARNESS_INFO**
  - The path to the harness info yaml. Containing path to binary and source.
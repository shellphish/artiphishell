# syzgrammar-gen

Generates a syzlang grammar for a C harness.

# Installation

`pip3 install -e .`

Note: The syzkaller path must include the patch from syzlangrs that makes syzkaller output the grammar as json.

# Usage

```
usage: syzgrammar-gen [-h] syzkaller_path harness_path joern_path out

positional arguments:
  syzkaller_path  The path of the syzkaller repository to use
  harness_path    The path to the harness
  joern_path      The path to the joern executable
  out             The output path for the grammar

options:
  -h, --help      show this help message and exit
```

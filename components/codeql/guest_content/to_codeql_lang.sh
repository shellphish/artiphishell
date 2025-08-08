#!/bin/bash

set -euo pipefail

LANGUAGE=cpp

LANGUAGE=$(python3 -c 'print(input().lower())' <<< "$1")
case "$1" in
c)
    LANGUAGE=cpp
    ;;
cpp)
    LANGUAGE=cpp
    ;;
go)
    LANGUAGE=go
    ;;
java)
    LANGUAGE=java
    ;;
javascript)
    LANGUAGE=javascript
    ;;
php)
    echo "PHP is not supported yet" >&2
    exit 1
    ;;
python)
    LANGUAGE=python
    ;;
ruby)
    LANGUAGE=ruby
    ;;
rust)
    echo "Rust is not supported yet" >&2
    exit 1
    ;;
typescript)
    LANGUAGE=typescript
    ;;
*)
    echo "Unknown language: $1" >&2
    exit 1
    ;;
esac
echo "$LANGUAGE"

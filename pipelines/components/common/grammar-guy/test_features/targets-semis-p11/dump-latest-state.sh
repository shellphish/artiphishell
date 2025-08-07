#!/bin/bash

set -e


rm -rf ./backup
pd backup ./backup/ --all 
# pd backup ./backup/ grammar_guy_fuzz 
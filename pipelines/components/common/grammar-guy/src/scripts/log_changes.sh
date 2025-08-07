#!/bin/bash
#

export GRAMMAR_PATH=$1

echo "LOGGING CHANGES"
pushd "${GRAMMAR_PATH}"
cp spearfuzz.g4 prev_grammar.g4
diff -u spearfuzz.g4 new_grammar.g4 >> "grammar_changes.patch" 
echo "----------------- diff until here ------------------" >> "grammar_changes.patch"
cp new_grammar.g4 "spearfuzz.g4"
popd
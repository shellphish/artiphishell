#!/bin/bash
#

# TODO add optional filetype. Default is .json; 
# TODO default grammarfile to first file in folder if not specified
# TODO automatically detect ClibJsonGenerator aka. generator module name
set -e #ux

export NUMINPUTS="$1"
export GRAMMAR_PATH="$2"
export OUT_DIR="$3" # /generated/input

TEMP_DIR=$(mktemp -d /tmp/grammar-guy-generators-XXXXX)
export GENERATORDIR=${TEMP_DIR}/generators
mkdir -p ${GENERATORDIR}
echo "SCR: GENERATORDIR ${GENERATORDIR}"

export GENDIR="${OUT_DIR}/tmp_hashes"
echo "SCR: GENDIR ${GENDIR}"
mkdir -p ${GENDIR}
grammarinator-process "$GRAMMAR_PATH" --rule="spearfuzz" -o "${GENERATORDIR}"
grammarinator-generate --sys-path="${GENERATORDIR}" "spearfuzzGenerator.spearfuzzGenerator" --rule "spearfuzz" -d "25" -o "${GENDIR}/spearfuzz_input_%d" -n "${NUMINPUTS}"

pushd ${GENDIR}
for file in $(ls -p ./ | grep -v /); do
    hash=$(md5sum ${file} | awk '{print $1}')
    mv ${GENDIR}/${file} ${OUT_DIR}/"${hash}"
done

rm -rf ${TEMP_DIR}
echo "SCR: DONE WITH THE GENERATION" 
popd 
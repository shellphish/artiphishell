#!/bin/bash

# set -x

# check if the ANTI_WRAP_LD_DEBUGGING environment variable is set
if [ ! -z "$ANTI_WRAP_LD_DEBUGGING" ]; then
    set -x
fi

# fake ld script for afl-clang-fast
# we have to parse out all the --wrap options and add them to files

# LD_LOGGING_OUTPUT_FILE="/out/.shellphish.ld_log.$(date +%s).txt"

# Array to store wrapped functions
wrapped_functions=()

# Array to hold arguments for the original linker
LD_ARGS=()

LIBRARIES_TO_PROTECT=(
    afl-compiler-rt.o
    libclang_rt.profile.a
    generic_harness.o
)
LIBRARIES_PROTECTED=()

[ ! -z "$ANTI_WRAP_LD_DEBUGGING" ] && echo "LD ARGUMENTS: $@"

# Parse the arguments to find --wrap=<function_name> and the library
for arg in "$@"; do
    if [[ "$arg" =~ --wrap=(.*) ]]; then
        function_name="${BASH_REMATCH[1]}"
        wrapped_functions+=("$function_name")
#        echo "Found wrapped function: $function_name" | tee -a "$LD_LOGGING_OUTPUT_FILE"

        # Pass the argument to the original linker
        LD_ARGS+=("$arg")
        continue
    fi
    
    if [[ -f $arg ]]; then
        [ ! -z "$ANTI_WRAP_LD_DEBUGGING" ] && cp "$arg" /out/latest-$(basename "$arg")-$(date +%s)
        if readelf -S -W "$arg" | grep -q ".shellphishshellphish"; then
            LIBRARIES_TO_PROTECT+=("$arg")
        fi
    fi

    arg_is_library=0

    for library_to_protect in "${LIBRARIES_TO_PROTECT[@]}"; do
        # fuzzy-match the library name
        if [[ "$arg" == *"$library_to_protect" ]]; then
            library=$(mktemp)
#            echo "Found protected library: $arg" | tee -a "$LD_LOGGING_OUTPUT_FILE"
            cp "$arg" "$library"

            # Pass the argument to the original linker
            LD_ARGS+=("$library")
            LIBRARIES_PROTECTED+=("$library")
            arg_is_library=1
        fi
    done
    if [ $arg_is_library -eq 0 ]; then
        LD_ARGS+=("$arg")
    fi
done

# If no protected library is found, exit with an error
# if [ ${#LIBRARIES_PROTECTED[@]} -eq 0 ]; then
#     echo "No protected library found" | tee -a "$LD_LOGGING_OUTPUT_FILE"
#     exit 1
# fi


# Create a temporary file to hold redefined symbols for objcopy
redefines_file=$(mktemp)

# Write redefined symbols into the file
for func in "${wrapped_functions[@]}"; do
    echo "${func} __real_${func}" >> "$redefines_file"
done
[ ! -z "$ANTI_WRAP_LD_DEBUGGING" ] && cp "$redefines_file" /out/latest-$(date +%s).redefines

#cat "$redefines_file" | tee -a "$LD_LOGGING_OUTPUT_FILE"

# Run objcopy with --redefine-syms to process the library
for library in "${LIBRARIES_PROTECTED[@]}"; do
#    echo "Processing library: $library" | tee -a "$LD_LOGGING_OUTPUT_FILE"
    objcopy --redefine-syms="$redefines_file" "$library"
#    echo objcopy --redefine-syms="$redefines_file" "$library" | tee -a "$LD_LOGGING_OUTPUT_FILE"
    [ ! -z "$ANTI_WRAP_LD_DEBUGGING" ] && cp "$library" /out/latest-$(basename "$library")-$(date +%s)
    
done

# Clean up temporary file
rm "$redefines_file"

#echo /usr/bin/ld.real "${LD_ARGS[@]}" | tee -a "$LD_LOGGING_OUTPUT_FILE"

# Call the original linker with the parsed arguments
/usr/bin/ld.real "${LD_ARGS[@]}" 2>&1 #| tee -a "$LD_LOGGING_OUTPUT_FILE"
EXIT_CODE=$?
#echo "Exit code: $EXIT_CODE" | tee -a "$LD_LOGGING_OUTPUT_FILE"

# cp "$auto_test_binary" /out/latest-autotest
exit $EXIT_CODE

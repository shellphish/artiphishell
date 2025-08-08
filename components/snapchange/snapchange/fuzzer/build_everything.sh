#!/bin/bash

set -ex

# Initialize the fuzz template for this example
init_fuzz_template() {
  # Add snapchange as dependency and build-dependency for this example
  $HOME/.cargo/bin/cargo add snapchange --path ../..
}

init_fuzz_template

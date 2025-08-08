add_library(FunctionCoverage MODULE
  src/FuncCov.cpp
)

target_compile_features(FunctionCoverage PRIVATE cxx_std_17)
target_compile_options(FunctionCoverage PRIVATE -fno-rtti -fPIC)

# Add LLVM include directories and definitions
target_include_directories(FunctionCoverage PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(FunctionCoverage PRIVATE ${LLVM_DEFINITIONS})

set_target_properties(FunctionCoverage PROPERTIES
  PREFIX ""
  SUFFIX ".so"
)
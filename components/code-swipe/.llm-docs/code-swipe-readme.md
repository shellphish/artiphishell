# Code Swipe Component

## Overview

Code Swipe is a multi-stage filtering and prioritization system designed to efficiently process large codebases. Its primary goal is to identify and prioritize potentially vulnerable or interesting code blocks, enabling focused analysis on the most critical sections first.

The component takes a large amount of target source code and filters it down to a smaller, prioritized set of code blocks (typically functions or methods) that warrant deeper security analysis. This helps optimize resource usage by ensuring that expensive analysis operations focus on the most promising targets first.

## Documentation Structure

This is a living document that will be updated as the component evolves. The documentation is structured as a tree, with additional documents maintained in the `.llm-docs` directory:

- `$CRS_ROOT/components/code-swipe/.llm-docs/architecture.md`: Detailed system design and component interaction
- `$CRS_ROOT/components/code-swipe/.llm-docs/filters.md`: Documentation for individual filter passes
- `$CRS_ROOT/components/code-swipe/.llm-docs/models.md`: Data structure and model specifications
- `$CRS_ROOT/components/code-swipe/.llm-docs/parallelization.md`: Parallelization strategy and implementation
- `$CRS_ROOT/components/code-swipe/.llm-docs/testing.md`: Comprehensive testing documentation

When implementing new features or making significant changes:
1. Update this README to reflect high-level changes
2. Update or create relevant documentation in the appropriate `.llm-docs` file
3. If creating new documentation files, add them to this list
4. Ensure cross-references between documents are maintained
5. Include implementation details and design decisions in the appropriate document
6. **IMPORTANT**: Always update the package structure section below when files are added, removed, or moved

## Package Structure
```
code-swipe/
├── src/
│   ├── __init__.py
│   ├── main.py              # Main entry point with CLI interface
│   ├── models/
│   │   ├── __init__.py
│   │   ├── code_block.py    # Core code block representation
│   │   ├── filter.py        # Filter pass base class
│   │   └── filter_result.py # Filter result model
│   ├── framework/
│   │   ├── __init__.py
│   │   └── filter_framework.py  # Filter orchestration
│   └── input/
│       ├── __init__.py
│       └── ingester.py      # Function index ingestion
├── tests/
│   ├── __init__.py
│   ├── conftest.py         # Test configuration
│   ├── test_models/
│   │   └── test_code_block.py
│   ├── test_framework/
│   │   └── test_filter_framework.py
│   └── test_input/
│       └── test_loaders.py
└── test-data/              # Test data for development
    └── clang_index.output_dir/
        └── samples/
            └── FUNCTION/   # Test function index files
```

## Key Objectives

1. **Reduction**: Transform large codebases (thousands of functions) into a prioritized list of ~100 high-interest code blocks
2. **Prioritization**: Rank code blocks by their likelihood of containing vulnerabilities
3. **Efficiency**: Process code quickly through parallelization and staged analysis
4. **Modularity**: Support multiple types of filtering and prioritization passes
5. **Integration**: Leverage existing CRS components' analysis results

## System Design

### Input Sources

1. **Primary Inputs**:
   - Target source code
   - Task information (delta mode changes or full mode base code)

2. **Secondary Inputs**:
   - Function index information (from Clang Indexer or Java equivalent)
   - CodeQL analysis results
   - Potential future inputs:
     - Harness information (QuickSeed/Grammar Guy)
     - Coverage data
     - Dynamic analysis results

### Core Components

1. **Collection System**:
   - Processes input data into analyzable blocks
   - Creates and manages code block representations
   - Provides search and iteration utilities
   - Handles vector embeddings for similarity analysis

2. **Code Block Model**:
   - Represents individual units of code (functions/methods)
   - Stores metadata and analysis results
   - Supports vector embeddings
   - Maintains priority scores and match information

3. **Filter Pass Framework**:
   - Manages the execution of filtering/prioritization passes
   - Handles pass ordering and dependencies
   - Supports parallel execution
   - Maintains scoring and ranking system

4. **Output Manager**:
   - Produces prioritized lists of code blocks
   - Includes relevant metadata and analysis results
   - Potential support for streaming high-priority findings

### Filtering Passes

Each pass contributes to the final priority score of a code block. The implementation priority indicates when the pass should be implemented, while the priority weight indicates how strongly the pass's findings influence the final ranking.

1. **Static Reachability Analysis**:
   - Implementation Priority: High (implement first)
   - Priority Weight: Low (baseline signal)
   - Description: Analyzes call graphs from harness entry points to identify reachable code
   - Features:
     - Static call graph analysis
     - Direct and indirect reachability tracking
     - Entry point identification
   - Considerations:
     - Will mark many functions as reachable
     - Serves as a baseline filter
     - May miss dynamically dispatched calls

2. **Dangerous Function Detection**:
   - Implementation Priority: High
   - Priority Weight: High
   - Description: Identifies known dangerous API calls and high-risk functions
   - Features:
     - Language-specific function matching
     - Configurable function lists
     - Context-aware severity assessment
   - Weights:
     - Critical functions (e.g., system, exec): Highest weight
     - Memory operations (e.g., strcpy): High weight
     - File operations: Medium-high weight
     - Database operations: Medium weight

3. **Pattern Matching**:
   - Implementation Priority: Medium
   - Priority Weight: Variable (Low to Very High)
   - Description: Multi-level pattern detection system
   - Features:
     - Keyword and regex-based analysis
     - Vector similarity matching
     - Code smell detection
     - Natural code analysis
   - Pattern Categories:
     - Command injection patterns (Very High weight)
     - Path traversal patterns (High weight)
     - Memory operation patterns (High weight)
     - SQL injection patterns (High weight)
     - General code smells (Low weight)
   - Implementation Notes:
     - Patterns should be easily extensible
     - Support for language-specific patterns
     - Context-aware pattern matching

4. **Harness Analysis**:
   - Implementation Priority: Medium
   - Priority Weight: Medium-High
   - Description: LLM-based analysis of harness intent and structure
   - Features:
     - Plugin/component identification
     - Entry point classification
     - Input type analysis
   - Analysis Types:
     - Direct harness analysis
     - Plugin interface analysis
     - Input validation patterns
   - Notes:
     - Focus on understanding harness purpose
     - Identify targeted functionality
     - Map harness coverage expectations

5. **Dynamic Coverage Analysis**:
   - Implementation Priority: Low
   - Priority Weight: Medium
   - Description: Runtime coverage and behavior analysis
   - Features:
     - Coverage data processing
     - Dynamic dispatch tracking
     - Reflection handling
   - Dependencies:
     - Coverage data availability
     - Quick seed results
     - Runtime instrumentation
   - Notes:
     - May require significant infrastructure
     - Handles edge cases missed by static analysis
     - Provides runtime validation

6. **LLM-Based Analysis**:
   - Implementation Priority: Low
   - Priority Weight: Very High
   - Description: Deep semantic code analysis
   - Features:
     - Vulnerability pattern detection
     - Logic bug identification
     - Code flow analysis
   - Analysis Types:
     - Path traversal detection
     - Command injection analysis
     - Logic flaw detection
     - Authentication bypass detection
   - Resource Constraints:
     - Only runs on pre-filtered code
     - Rate-limited API usage
     - Parallel execution management
   - Notes:
     - Most expensive analysis type
     - Highest signal-to-noise ratio
     - Requires careful prompt engineering

## Implementation Roadmap

### Phase 1: Foundation (Core Infrastructure)
0. Create a main.py which will be the entry point for the component
   - Should take paths to the source code and function index
1. Core data structures and models
   - Code block representation owning the models in the `shellphish_crs_utils` library, but with extra metadata we will use to update the results from the filter passes
   - Classes for the filter applier system
      - Structure of class which will implement the filter pass framework, registering each filter pass, and then running each pass one at a time in sequence
      - Base class for a filter pass type
      - Base class for a filter pass result type
      - Structure of class for the output manager which will be responsible for taking the results from the filter passes and formatting them into the final output

2. Input processing system
   - Loading the all data from the function index into the code block representation and storing that in the framework class instance
3. Initial testing framework
   - Unit test infrastructure
   - Testing using provided test-data

### Phase 2: Basic Filtering (Essential Features)
1. Static reachability analysis
   - Call graph construction
   - Entry point tracking
   - Reachability scoring
2. Dangerous function detection
   - Function database creation
   - Language-specific matchers
   - Context analysis
3. Simple pattern matching
   - Basic regex system
   - Initial pattern database
   - Weight configuration
4. Initial output format
   - Priority scoring system
   - Metadata formatting
   - Result serialization

### Phase 3: Advanced Analysis (Enhanced Features)
1. Vector embeddings
   - Code embedding generation
   - Similarity matching
   - Clustering support
2. Harness analysis
   - LLM integration
   - Plugin detection
   - Intent analysis
3. Enhanced pattern matching
   - Complex pattern support
   - Context-aware matching
   - Custom pattern creation
4. Streaming output support
   - Real-time result streaming
   - Priority threshold system
   - Incremental updates

### Phase 4: Integration & Optimization (System Maturity)
1. Dynamic coverage integration
   - Coverage data processing
   - Runtime analysis
   - Behavior tracking
2. LLM analysis implementation
   - Vulnerability detection
   - Logic analysis
   - Rate limiting
3. Performance optimization
   - Caching system
   - Memory management
   - Processing optimization
4. Full parallelization
   - Distributed processing
   - Load balancing
   - Resource optimization

### Phase 5: Testing & Validation (Quality Assurance)
1. Integration test suite
   - End-to-end testing
   - Component interaction tests
   - Error handling validation
2. Performance benchmarking
   - Speed measurements
   - Resource monitoring
   - Scalability testing
3. Known vulnerability validation
   - Test case creation
   - Vulnerability detection
   - False positive analysis

## Development Guidelines

1. Use CRS utilities for:
   - Input/output models
   - Coverage library integration
   - Common functionality

2. Maintain documentation:
   - Update this README as features are added
   - Create/update specific docs for new features
   - Document design decisions and trade-offs

3. Performance considerations:
   - Design for parallelization from the start
   - Monitor and optimize resource usage
   - Consider rate limits for LLM analysis

4. Testing requirements:
   - Focus on unit tests during initial development
   - Integration tests in later phases
   - Document test cases and coverage

## Notes

- This component is designed to be extended with additional filtering passes
- Performance and resource usage should be carefully monitored
- Integration with other CRS components will evolve over time
- Documentation should be updated as new features are implemented

## Initial Code Structure Brainstorming

### Core Package Structure
```
code-swipe/
├── src/
│   ├── collection/
│   │   ├── parser.py        # Source code parsing
│   │   ├── indexer.py       # Code block indexing
│   │   └── embeddings.py    # Vector embedding generation
│   ├── models/
│   │   ├── code_block.py    # Code block representation
│   │   ├── filter_pass.py   # Filter pass base classes
│   │   └── priority.py      # Priority scoring system
│   ├── filters/
│   │   ├── base.py          # Filter pass framework
│   │   ├── reachability.py  # Static reachability
│   │   ├── dangerous.py     # Dangerous function detection
│   │   └── patterns.py      # Pattern matching system
│   ├── analysis/
│   │   ├── harness.py       # Harness analysis
│   │   ├── coverage.py      # Coverage processing
│   │   └── llm.py          # LLM-based analysis
│   └── output/
│       ├── manager.py       # Output management
│       ├── streaming.py     # Streaming support
│       └── formatter.py     # Result formatting
```

### Implementation Notes

1. **Priority Scoring**:
   - Initial implementation will use simple additive scoring
   - Multiple matches from same pass use highest weight
   - All match information preserved in metadata
   - Scoring algorithm can be refined based on testing with known vulnerabilities

2. **Code Block Granularity**:
   - Initially process at function/method level
   - Use existing function index information from Clang Indexer
   - Future enhancement: Break down large functions into semantic blocks
   - For delta analysis, entire functions are analyzed if touched by changes

3. **Language Support**:
   - Initial support for C and Java only
   - Language-specific metadata (e.g., Java class information) included when available
   - Rely on pre-parsed information from function indexing
   - Use string matching and LLM analysis to avoid complex parsing

4. **Delta Mode Processing**:
   - Initially focus only on changed functions
   - Consider entire function if any part is modified
   - Future enhancement: Analysis of exposed base code vulnerabilities

5. **Component Integration**:
   - Required input: Function index information (from CRS utils models)
   - Optional inputs: CodeQL analysis, coverage data
   - Component continues with reduced functionality if optional inputs unavailable
   - Output format will be defined in Pydantic models

6. **Resource Management**:
   - Configurable CPU parallelization
   - Most passes designed for quick execution
   - LLM analysis parallelized within rate limits
   - Prioritize high-value targets for expensive analysis

7. **Error Handling**:
   - Individual pass failures contained to specific functions
   - Component continues processing on errors
   - Errors recorded in result metadata
   - No critical failures unless input data invalid

8. **Future Enhancements**:
   - Streaming output for high-confidence matches
   - Enhanced base code analysis in delta mode
   - Advanced scoring algorithms
   - Large function segmentation

### Parallelization Strategy

**Pass-Level Parallelization**:
   - Run independent passes concurrently
   - Maintain pass dependencies
   - Resource-aware scheduling

# Testing Data

Currently there are two dirs with the inputs which can be consumed by this component:
- `./test-data/clang_index.output_dir` - Contains the json indexed output from the clang indexer. It contains json files which can be loaded and pass into the models in the `shellphish_crs_utils` library via the models under `$CRS_ROOT/libs/crs-utils/src/shellphish_crs_utils/models/indexer.py`
- `./test-data/pipeline_inputs.target_with_sources` - This contains the source of the target project. It should be accessed through the `shellphish_crs_utils` library via the `OSSFuzzProject` class in `$CRS_ROOT/libs/crs-utils/src/shellphish_crs_utils/oss_fuzz/project.py`, see that file for more details.

### Initial Implementation Plan

1. Start with the core models and basic collection system
2. Implement the filter pass framework
3. Add static reachability analysis
4. Build dangerous function detection
5. Develop basic pattern matching
6. Create initial output system

This structure allows for:
- Clear separation of concerns
- Easy extension of filter passes
- Flexible priority scoring
- Efficient parallel processing
- Comprehensive metadata tracking


# TODO tracking
As you go update the todo file for each phase marking off the items as you complete them (but only after approved by the human reviewer)

# Code Requirements
- Always use python3 type hints and docstrings
- When creating new classes you should use the pydantic BaseModel

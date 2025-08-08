# ARTIPHISHELL - Cyber Reasoning System Documentation

## Project Overview

ARTIPHISHELL is a Cyber Reasoning System (CRS) developed for the DARPA AI Cyber Challenge (AIXCC). The system's primary objectives are:

1. Analyze source code to identify vulnerabilities
2. Generate Proof of Vulnerability (POV) demonstrations
3. Create patches to remediate discovered vulnerabilities

## Terminology

### Core Concepts
- **Target**: An open-source project provided for analysis. Each target is a unique codebase that needs to be examined for vulnerabilities.
- **Task**: A specific unit of work within a target, which may include:
  - A section of source code to analyze
  - A change in source code to evaluate
  - An identified vulnerability with a patch in SARIF format
- **Component**: A compartmentalized part of our system that may contain multiple pydatatask tasks. For example, a component might include:
  - A build task for compiling the target
  - An indexing task for code analysis
  - A main task for core functionality
- **Pipeline**: YAML configuration files for pydatatask. Components typically have their own pipeline files which are included in higher-level pipelines.
- **Data Repo**: A pydatatask concept representing a data storage and transfer mechanism between tasks (not to be confused with git repositories).

### Analysis Modes
- **Delta-scan**: Analysis mode where we receive a base codebase and a set of changes. These changes may introduce new vulnerabilities or expose existing ones in the base code.
- **Full-scan**: Analysis mode where we analyze the base source code without changes, searching for vulnerabilities in any reachable code.

### Technical Terms
- **Sanitizer**: Runtime detection system for vulnerabilities. Implementation varies by language:
  - C/C++: Address Sanitizer
  - Java: Jazzer
- **Harness**: Entry point programs that utilize parts of the target, used by fuzzers and POV inputs. Each target has multiple harnesses to determine reachable code.
- **OSS Fuzz**: Google's standardized format for fuzzing targets, including:
  - Build scripts
  - Multiple harnesses
  - Standardized harness execution
- **Instrumentation**: Techniques to monitor running targets, used to:
  - Track function calls
  - Locate interesting functions
  - Detect behavior changes based on inputs

### Reporting and Verification
- **SARIF**: Standard format for:
  - Receiving existing vulnerability information
  - Reporting newly discovered vulnerabilities
  - Documenting patches and additional vulnerability details
- **POV** (Proof of Vulnerability): Required demonstration that proves a vulnerability is real and exploitable. Required for point submission.

### Competition Terms
- **AFC** (AIxCC Finals Competition): The finals phase of the DARPA AI Cyber Challenge
- **ASC** (AIxCC Semifinals Competition): The semifinals phase of the DARPA AI Cyber Challenge

## System Architecture

### Data Pipeline Architecture

ARTIPHISHELL operates as a data pipeline powered by pydatatask where:

1. Components are scheduled tasks within the pipeline
2. Data flows between components through data repos, which can be:
   - File system repos (containing raw files)
   - Metadata repos (containing YAML data)
   - Streaming repos (for continuous data flow)
3. Data repos can be keyed (e.g., by target ID) to maintain separate instances
4. Tasks only start when all their required input repos contain data

### Component Dependencies

Dependencies in the system are managed through:

1. **Data Dependencies**:
   - Defined in pipeline YAML files
   - Tasks only launch when required input repos have data
   - Dependencies can be tracked through pipeline configurations

2. **Library Dependencies**:
   - Core shared libraries:
     - `crs_utils`: Common utilities and models
     - `agent_lib`: LLM and agent functionality
     - `coverage_lib`: Target code coverage collection
   - Component-specific dependencies defined in Dockerfiles

### Resource Management

Resource allocation is strictly controlled:
- Defined in pipeline YAML files
- Managed by pydatatask
- Resources are allocated from a shared pool
- Resource settings should only be modified by humans
- Competition has strict compute and LLM usage budgets

### Error Handling

The system emphasizes robust error handling:
- Components must handle errors cleanly and provide appropriate outputs
- Use pydantic models to ensure type safety
- Careful exception handling for all external interactions
- Fallback mechanisms require human oversight
- Future telemetry system will track failures

## Repository Structure

This is a large monorepo containing all components of the CRS. Below is a guide to the major directories and their purposes:

### `/components`
Contains individual pipeline components that process data and produce outputs. Components fall into several categories:

- **Long-running Components**: Continuous processors like fuzzers (e.g., AFL++)
- **Single-processing Components**: One-time processors like the Clang indexer
- **Event-driven Components**: Tasks that trigger on specific events (e.g., POV-Guy for crash validation)

### `/libs`
Shared libraries used across multiple components:

- `pydatatask`: Core pipeline scheduling library
- `agent_lib`: LLM-based and agentic task implementations
- `crs_utils`: Common utilities and Pydantic models for cross-component communication

### `/docker`
Base Docker images used as foundations for component-specific images. Changes here should be minimal as they affect build times across the system.

### `/pipelines`
Contains pydatatask pipeline definitions that orchestrate component interactions. Due to their complexity, changes should be carefully reviewed.

### `/aixcc-infra`
DARPA-provided infrastructure code for local testing. This directory should not be modified as it's maintained upstream.

## Documentation Structure

The repository uses `.llm-docs` directories throughout the codebase to provide LLM-friendly documentation. When working with specific components or libraries, look for these directories for detailed guidance.

## Important Notes for LLMs

1. **Context Management**: Due to the large size of this codebase, be selective about loading files into context. Use this documentation to identify relevant code sections before loading them.

2. **Component Interactions**: When making changes, consider:
   - Cross-component data types defined in `libs/crs_utils/models`
   - Pipeline dependencies in the `pipelines` directory
   - Docker image implications for library changes
   - Data flow through repos between components

3. **Code Organization Guidelines**:
   - Shared functionality should only be added to `libs` if used by multiple components
   - All cross-component data types must be defined in CRS utils models
   - Component-specific code should remain within its component directory
   - Changes affecting multiple components must be coordinated in a single pull request

4. **Error Handling Requirements**:
   - Always handle exceptions cleanly
   - Use pydantic models for type safety
   - Provide meaningful error outputs
   - Don't implement fallback logic without human oversight

## Navigation Guide

When working on tasks in this repository:

1. Start with this document to understand the overall structure
2. Look for `.llm-docs` in relevant subdirectories for specific guidance
3. Use semantic search to locate relevant code only after identifying the correct component or library
4. Verify changes against the pipeline structure when modifying component interactions

## Target Building

Currently, each component is responsible for building its own copy of the target source code into compiled artifacts for analysis. This approach may lead to resource constraints as multiple components might build the same target simultaneously. A future improvement may involve transitioning to a dedicated builder service to centralize and optimize the build process for targets.

## Version Control and Changes

- This is a monorepo where all components on a branch should be compatible
- Changes are made through pull requests
- Interdependent changes must be in the same pull request
- Branches should remain functional when merged
- Sometimes upstream changes need to be merged or cherry-picked to maintain functionality

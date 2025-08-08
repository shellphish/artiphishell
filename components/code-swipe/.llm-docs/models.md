# Code Swipe Models

## Core Models

### CodeBlock
The central model representing a block of code (typically a function) that will be analyzed and filtered.

```python
class CodeBlock(ShellphishBaseModel):
    # Core information from function index
    function_info: FunctionIndex  # Direct use of CRS utils FunctionIndex model
    
    # Analysis metadata
    priority_score: Optional[float]  # Calculated from filter results
    
    # Filter results - keyed by filter name
    filter_results: Dict[str, FilterResult]
```

### FilterResult
Represents the result of running a single filter on a code block.

```python
class FilterResult(ShellphishBaseModel):
    weight: float  # Weight/strength of the match (0.0 to 1.0)
    metadata: Dict[str, Any]  # Additional filter-specific metadata
```

### FilterPass
Abstract base class for implementing filter passes.

```python
class FilterPass(ShellphishBaseModel, ABC):
    name: str  # Unique name of this filter pass
    enabled: bool  # Whether this filter is currently enabled
    config: Dict  # Filter-specific configuration options
    
    @abstractmethod
    def process(self, code_block: CodeBlock) -> FilterResult:
        pass
```

## Framework Models

### FilterFramework
Orchestrates the execution of filter passes over code blocks.

```python
class FilterFramework(ShellphishBaseModel):
    registered_passes: Dict[str, FilterPass]
    execution_order: List[str]  # Order of filter execution
    global_config: Dict
```

## Input Models

### FunctionIndexIngester
Handles loading and transforming function index data into CodeBlock instances.

```python
class FunctionIndexIngester(ShellphishBaseModel):
    index_dir: Path  # Directory containing function index files
```

## Model Relationships

1. `CodeBlock` contains a `FunctionIndex` from CRS utils for core function data
2. `CodeBlock` stores `FilterResult`s from each filter pass
3. `FilterPass` processes a `CodeBlock` and produces a `FilterResult`
4. `FilterFramework` manages `FilterPass`es and processes collections of `CodeBlock`s
5. `FunctionIndexIngester` creates `CodeBlock`s from function index files

## Implementation Notes

- All models are Pydantic models (inherit from `ShellphishBaseModel`)
- External data models (like `FunctionIndex`) are used directly from CRS utils
- Filter results are stored with their full context rather than just scores
- Priority scoring is separated from filter execution for flexibility

*This document will be updated as models are implemented and refined.* 
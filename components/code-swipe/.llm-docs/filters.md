# Code Swipe Filters

## Filter Framework

### Core Concepts
- Each filter is a separate pass over code blocks
- Filters can run independently or in sequence
- Results contribute to final priority score
- Metadata preserved for all matches

## Implementation Priority

### Phase 1 (Initial Release)
1. Static Reachability Analysis
2. Dangerous Function Detection
3. Basic Pattern Matching

### Phase 2 (Enhanced Features)
1. Vector Similarity Matching
2. Harness Analysis
3. Complex Pattern Matching

### Phase 3 (Advanced Features)
1. LLM Analysis
2. Dynamic Coverage Analysis

## Scoring System

### Weight Categories
- Very High: Direct vulnerability indicators (red flags)
- High: Strong security concerns
- Medium: Potential issues
- Low: General indicators
- Variable: Context-dependent

### Score Calculation
- Initial implementation: Additive scoring
- Multiple matches: Highest weight used
- All matches preserved in metadata
- Refinement based on testing

## Filter Details
These should be fleshed out as we implement the filters to have a lot more detail on the actual implementation

### Static Reachability
- Base priority indicator
- Call graph analysis
- Entry point tracking
- Language-specific handling

### Dangerous Functions
- Configurable function lists
- Severity-based weights
- Context awareness
- Language-specific patterns

### Pattern Matching
- Regex-based matching
- Vector similarity
- Code smell detection
- Extensible patterns

### Harness Analysis
- LLM-based intent analysis
- Plugin detection
- Input validation
- Coverage mapping

### Dynamic Coverage
- Runtime data processing
- Behavior tracking
- Edge case detection
- Optional enhancement

### LLM Analysis
- Deep semantic analysis
- Vulnerability detection
- Logic flow analysis
- Rate-limited execution

## Error Handling

### Per-Filter Recovery
- Contained failures
- Partial results
- Fallback options (maybe)
- Error reporting

## Future Extensions

### Planned Enhancements
- Additional pattern types
- Enhanced scoring models
- Language-specific filters
- Performance optimization

### Integration Points
- Coverage integration
- CodeQL enhancement
- Streaming results
- Cross-component coordination

*This document will be updated as filters are implemented and refined.* 
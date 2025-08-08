import ast
import re
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import math

@dataclass
class FunctionMetrics:
    """Lightweight container for function complexity metrics"""
    name: str
    complexity_score: float
    line_count: int
    hash_signature: str

    def __post_init__(self):
        # Ensure consistent scoring across invocations
        self.normalized_score = self._normalize_score()

    def _normalize_score(self) -> float:
        """Normalize score to 0-100 range for consistent comparison"""
        # Use logarithmic scaling to handle wide score ranges
        return min(100.0,
                   max(0.0,
                       math.log10(max(1.0, self.complexity_score)) * 20))

class FunctionRanker:
    """
    Efficient function ranker for identifying hard-to-reach coverable lines.
    Optimized for memory efficiency with large codebases (28k+ functions).
    """

    def __init__(self,
                 weight_cyclomatic: float = 0.3,
                 weight_nesting: float = 0.25,
                 weight_exception: float = 0.2,
                 weight_branching: float = 0.15,
                 weight_length: float = 0.08):  # slightly reduced impact of length
        """
        Initialize ranker with configurable weights for different complexity factors.
        Args:
            weight_cyclomatic: Weight for cyclomatic complexity
            weight_nesting: Weight for nesting depth
            weight_exception: Weight for exception handling complexity
            weight_branching: Weight for branching complexity
            weight_length: Weight for function length
        """
        self.weights = {
            'cyclomatic': weight_cyclomatic,
            'nesting': weight_nesting,
            'exception': weight_exception,
            'branching': weight_branching,
            'length': weight_length
        }

        # Memory-efficient storage for function signatures
        self._function_cache: Dict[str, FunctionMetrics] = {}
        self._complexity_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Pre-compile regex patterns for efficiency"""
        return {
            'nested_conditions': re.compile(r'\b(if|while|for)\b.*?\b(if|while|for)\b', re.MULTILINE),
            'exception_blocks': re.compile(r'\b(?:try|catch|finally|throw)\b', re.IGNORECASE | re.MULTILINE),
            'complex_expressions': re.compile(r'[&|]{2}|\?.*?:|switch\s*\(', re.MULTILINE),
            'nested_loops': re.compile(r'for\s*\([^)]*\)\s*\{[^}]*for\s*\(', re.MULTILINE),
            'callback_patterns': re.compile(r'callback|listener|handler|observer', re.IGNORECASE)
        }

    def _clean_code(self, source: str) -> str:
        """
        Strip out Java/C comments and string/char literals so regex only
        sees real keywords.
        """
        # Remove block comments
        code = re.sub(r'/\*[\s\S]*?\*/', '', source)
        # Remove line comments
        code = re.sub(r'//.*', '', code)
        # Remove double-quoted strings
        code = re.sub(r'"(?:\\.|[^"\\])*"', '', code)
        # Remove single-quoted chars
        code = re.sub(r"'(?:\\.|[^'\\])*'", '', code)
        return code

    def _generate_function_hash(self, name: str, source_code: str) -> str:
        """Generate consistent hash for function identification across invocations"""
        try:
            signature_data = f"{name}\n{source_code.strip()}"
            return hashlib.md5(signature_data.encode('utf-8')).hexdigest()[:16]
        except Exception:
            return hashlib.md5(f"{name}:{len(source_code)}".encode('utf-8')).hexdigest()[:16]

    def _calculate_cyclomatic_complexity(self, source_code: str) -> int:
        """Calculate cyclomatic complexity efficiently using AST when possible"""
        try:
            tree = ast.parse(source_code)
            complexity = 1
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                    complexity += 1
                elif isinstance(node, ast.ExceptHandler):
                    complexity += 1
                elif isinstance(node, (ast.BoolOp, ast.Compare)):
                    complexity += len(getattr(node, 'ops', [])) or len(getattr(node, 'values', [])) - 1
            return complexity
        except SyntaxError:
            return self._pattern_based_complexity(source_code)

    def _pattern_based_complexity(self, source_code: str) -> int:
        """Fallback complexity calculation using regex patterns"""
        code = self._clean_code(source_code)
        complexity = 1
        decision_keywords = ['if', 'else if', 'elseif', 'elif', 'while', 'for', 'case', 'catch']
        for keyword in decision_keywords:
            complexity += len(re.findall(rf"\b{keyword}\b", code, re.IGNORECASE))
        complexity += len(re.findall(r'&&|\|\||and\s|or\s', code, re.IGNORECASE))
        return complexity

    def _calculate_nesting_depth(self, source_code: str) -> int:
        """Calculate maximum nesting depth"""
        lines = source_code.split('\n')
        max_depth = 0
        stack = []
        char_pairs = {'{': '}', '(': ')', '[': ']'}
        for line in lines:
            cleaned_line = re.sub(r'".*?"|\'.*?\'|//.*|/\*[\s\S]*?\*/', '', line)
            for char in cleaned_line:
                if char in char_pairs:
                    stack.append(char)
                    max_depth = max(max_depth, len(stack))
                elif stack and char == char_pairs.get(stack[-1]):
                    stack.pop()
        return max_depth

    def _calculate_exception_complexity(self, source_code: str) -> int:
        """
        Exception complexity for Java/C only:
         - 1 point per try/catch/finally/throw
         - +2 bonus for each nested try
        """
        clean = self._clean_code(source_code)
        count_try     = len(re.findall(r"\btry\b", clean))
        count_catch   = len(re.findall(r"\bcatch\b", clean))
        count_finally = len(re.findall(r"\bfinally\b", clean))
        count_throw   = len(re.findall(r"\bthrow\b", clean))
        base_score    = count_try + count_catch + count_finally + count_throw
        nested_tries  = len(re.findall(r"\btry\b[\s\S]*?\btry\b", clean))
        nested_bonus  = nested_tries * 2
        return base_score + nested_bonus

    def _calculate_branching_complexity(self, source_code: str) -> int:
        """Calculate branching complexity"""
        code = self._clean_code(source_code)
        branching_score = 0
        branching_score += len(re.findall(r"\bswitch\s*\(", code, re.IGNORECASE))
        branching_score += len(self._complexity_patterns['complex_expressions'].findall(code))
        branching_score += len(self._complexity_patterns['nested_conditions'].findall(code))
        branching_score += len(re.findall(r"\?[^:]*:", code))
        return branching_score

    def analyze_function(self,
                         function_name: str,
                         source_code: str) -> Optional[FunctionMetrics]:
        """
        Analyze a single function and return its complexity metrics.
        """
        if not function_name or not source_code:
            return None
        func_hash = self._generate_function_hash(function_name, source_code)
        if func_hash in self._function_cache:
            return self._function_cache[func_hash]
        # Clean once
        cleaned = self._clean_code(source_code)
        cyclomatic = self._calculate_cyclomatic_complexity(source_code)
        nesting    = self._calculate_nesting_depth(source_code)
        exception  = self._calculate_exception_complexity(source_code)
        branching  = self._calculate_branching_complexity(source_code)
        length     = len(source_code.split('\n'))
        normalized_cyclomatic = min(50, cyclomatic)
        normalized_nesting    = min(20, nesting * 5)
        normalized_exception  = min(30, exception * 3)
        normalized_branching  = min(25, branching * 2.5)
        normalized_length     = min(25, length / 5)  # slightly less impact
        complexity_score = (
            self.weights['cyclomatic'] * normalized_cyclomatic +
            self.weights['nesting']     * normalized_nesting +
            self.weights['exception']   * normalized_exception +
            self.weights['branching']   * normalized_branching +
            self.weights['length']      * normalized_length
        )
        metrics = FunctionMetrics(
            name=function_name,
            complexity_score=complexity_score,
            line_count=length,
            hash_signature=func_hash
        )
        if len(self._function_cache) < 10000:
            self._function_cache[func_hash] = metrics
        return metrics

    def rank_functions(self,
                      functions: List[Tuple[str, str]],
                      top_k: Optional[int] = None) -> List[FunctionMetrics]:
        """
        Rank functions by complexity score.
        """
        metrics_list = []
        for func_name, source_code in functions:
            metrics = self.analyze_function(func_name, source_code)
            if metrics:
                metrics_list.append(metrics)
        sorted_metrics = sorted(metrics_list, key=lambda m: m.normalized_score, reverse=True)
        return sorted_metrics[:top_k] if top_k else sorted_metrics

    def compare_functions(self, metrics_list: List[FunctionMetrics]) -> List[FunctionMetrics]:
        """
        Compare and re-rank functions from different invocations.
        """
        unique_functions = {}
        for metrics in metrics_list:
            sig = metrics.hash_signature
            if sig not in unique_functions or metrics.normalized_score > unique_functions[sig].normalized_score:
                unique_functions[sig] = metrics
        return sorted(unique_functions.values(), key=lambda m: m.normalized_score, reverse=True)

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics for monitoring memory usage"""
        return {
            'cached_functions': len(self._function_cache),
            'memory_usage_estimate': len(self._function_cache) * 200
        }

    def clear_cache(self):
        """Clear function cache to free memory"""
        self._function_cache.clear()

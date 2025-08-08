import hashlib
from pathlib import Path
from typing import List, Optional
from neomodel import StructuredNode, StructuredRel, RelationshipTo, RelationshipFrom
from neomodel import StringProperty, BooleanProperty, IntegerProperty, DateTimeProperty, JSONProperty, RegexProperty, ArrayProperty

class LLMGrammarMutationRelationShip(StructuredRel):
    convo_langsmith_id = StringProperty()
    improvement_report = StringProperty(required=True)
    llm_conversation = StringProperty(required=True)

class Grammar(StructuredNode):
    grammar_type = StringProperty(required=True, choices={k: k for k in [
        'syzlang', 'grammarinator', 'nautilus-python', 'nautilus-py', 'nautilus-json', 'python'
    ]})
    hash = StringProperty(required=True, unique_index=True)
    grammar = StringProperty(required=True)

    llm_mutated_from = RelationshipFrom('Grammar', 'LLM_MUTATED_FROM', model=LLMGrammarMutationRelationShip)

    covered_functions = RelationshipTo('CFGFunction', 'COVERS')
    covered_lines = RelationshipTo('CoveredFunctionLine', 'COVERS')

    @classmethod
    def ensure_exists(cls, grammar_type: str, grammar: str):
        grammar_hash = hashlib.sha256(grammar.encode()).hexdigest()
        return cls.get_or_create({
            'grammar_type': grammar_type,
            'grammar': grammar,
            'hash': grammar_hash
        })[0]


from analysis_graph.models.cfg import CFGFunction
from analysis_graph.models.coverage import CoveredFunctionLine

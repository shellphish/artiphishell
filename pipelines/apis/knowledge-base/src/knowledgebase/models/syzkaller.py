import os
import git
from neomodel import StructuredNode, RelationshipTo, RelationshipFrom, Relationship, StructuredRel
from neomodel import StringProperty, IntegerProperty, BooleanProperty, ArrayProperty
from neomodel import ZeroOrMore, One, ZeroOrOne, FloatProperty


from .vulnerability_patches import VulnerabilityPatch
from .git_repo import SourceFile, Commit
from ..models.cve import CWE


import hashlib

#########################################################################
class SyzCrash(StructuredNode):

    crash_title = StringProperty(required=True)
    crash_report = StringProperty()
    parsed_report = StringProperty()

    patch_node = RelationshipTo('VulnerabilityPatch', 'SYZCRASH_PATCH', cardinality=ZeroOrMore)
    c_repro = RelationshipTo('SyzReproC', 'SYZCRASH_C_REPRO', cardinality=ZeroOrMore)
    syz_repro = RelationshipTo('SyzProg', 'SYZCRASH_SYZPROG_REPRO', cardinality=ZeroOrMore)

    cwe_info = RelationshipTo('CWE', 'CWE', cardinality=ZeroOrMore)

class SyzReproC(StructuredNode):

    source = StringProperty(required=True)
    embeddings = ArrayProperty(FloatProperty())

class SyzProg(StructuredNode):

    identifier = StringProperty(required=True, unique_index=True)
    source = StringProperty(required=True)
    embeddings = ArrayProperty(FloatProperty())

    @staticmethod
    def get_identifier(syzprog):
        identifier = hashlib.md5(syzprog.encode('utf-8')).hexdigest()
        return identifier


class SyzProgCoversBB(StructuredRel):

    # list of commit hashes where the syzprog executed the basic block
    seen_in_commits = StringProperty(default='')


class BasicBlock(StructuredNode):

    identifier = StringProperty(required=True, unique_index=True)
    function = StringProperty(required=True)
    file = StringProperty(required=True)
    source_lines = StringProperty(required=True)

    # contained_in_file = RelationshipFrom('SourceFile', 'FILE_CONTAINS_BASICBLOCK', cardinality=One)
    
    triggered_by_syzprog = RelationshipFrom('SyzProg', 'SYZPROG_TRIGGER_BASICBLOCK', cardinality=ZeroOrMore, model=SyzProgCoversBB)


    @staticmethod
    def clean_up_source(source_lines):
        no_white_space_source = ' '.join(source_lines.split())
        return no_white_space_source

    @staticmethod
    def get_identifier(file_path, function_name, source_lines):
        identifier_string = f'{file_path}::{function_name}::{source_lines}'
        identifier = hashlib.md5(identifier_string.encode('utf-8')).hexdigest()
        return identifier


    # TODO - add more fields here based on the dataset
    
class CrashReport(StructuredNode):
    report_type = StringProperty(required=True)
    report_content = StringProperty(required=True)
    report_embeddings = ArrayProperty(FloatProperty())

    sanitizer = StringProperty()
    severity = StringProperty()

    patch_node = RelationshipTo('VulnerabilityPatch', 'CRASH_PATCH', cardinality=ZeroOrMore)


class CrashConfig(StructuredNode):

    @staticmethod
    def get_identifier(config, commit, time):
        identifier_string = f'{config}::{commit}::{str(time)}'
        identifier = hashlib.md5(identifier_string.encode('utf-8')).hexdigest()
        return identifier

    identifier = StringProperty(required=True, unique_index=True)    
    config = StringProperty()
    crash_commit = StringProperty()
    crash_time = IntegerProperty()
    config_of = RelationshipFrom('SyzCrash', 'CRASH_CONFIG', cardinality=ZeroOrOne)
# This one has to be in this weird subfolder because of the way `import git` would break if a `git.py` file existed

import os
import git
from neomodel import StructuredNode, RelationshipTo, RelationshipFrom, Relationship
from neomodel import StringProperty, IntegerProperty, BooleanProperty, ArrayProperty
from neomodel import ZeroOrMore, One, ZeroOrOne, FloatProperty

#########################################################################
class TargetRepository(StructuredNode):

    targetPath = StringProperty(required=True, unique_index=True)

class SourceRepository(StructuredNode):

    isClosestToTarget = BooleanProperty(required=True)
    repo = StringProperty(required=True)
    fromCommit = StringProperty(required=True)
    distanceToTarget = FloatProperty(required=True) # this will be the distance based on find_closest_commit.py

    commit_rel = RelationshipFrom('Commit', 'SOURCE_BASED_ON_COMMIT')

class FileContent(StructuredNode):

    contents_of_file = RelationshipFrom('SourceFile', 'FILE_CONTENTS')
    sourceCode = StringProperty()
    embeddings = ArrayProperty(FloatProperty())

    version_at_source = RelationshipFrom('SourceRepository', 'FILE_AT_SOURCE', cardinality=ZeroOrOne)
    version_at_target = RelationshipFrom('TargetRepository', 'FILE_AT_TARGET', cardinality=ZeroOrOne)

class FunctionContent(StructuredNode):

    contained_in = RelationshipFrom('FileContent', 'FILE_CONTAINS_FUNCTION')

    identifier = StringProperty(required=True)

    fullName = StringProperty(required=True)
    signature = StringProperty(required=True)
    returnType = StringProperty(required=True)
    accessModifier = StringProperty(required=True)

    sourceCode = StringProperty()
    embeddings = ArrayProperty(FloatProperty())

class FileModification(StructuredNode):

    modified_file = RelationshipTo('SourceFile', 'FILE_MODIFICATION')

    diffText = StringProperty()
    diffEmbeddings = ArrayProperty(FloatProperty())

    beforePatchSourceCode = StringProperty()
    beforePatchEmbeddings = ArrayProperty(FloatProperty())

    afterPatchSourceCode = StringProperty()
    afterPatchEmbeddings = ArrayProperty(FloatProperty())

class FunctionModification(StructuredNode):

    identifier = StringProperty(required=True)

    fullName = StringProperty(required=True)
    signature = StringProperty(required=True)
    returnType = StringProperty(required=True)
    accessModifier = StringProperty(required=True)

    patchDiff = StringProperty()
    patchDiffEmbeddings = ArrayProperty(FloatProperty())

    beforePatchSourceCode = StringProperty()
    beforePatchEmbeddings = ArrayProperty(FloatProperty())

    afterPatchSourceCode = StringProperty()
    afterPatchEmbeddings =  ArrayProperty(FloatProperty())

    contained_in = RelationshipFrom('FileModification', 'FUNCTION_MODIFICATION')

#########################################################################

class SourceFile(StructuredNode):
    path = StringProperty(unique_index=True)

    renamed_to = RelationshipFrom('SourceFile', 'RENAMED_TO')

    touched_by_commit = RelationshipFrom('Commit', 'TOUCHED_FILE')
    created_by_commit = RelationshipFrom('Commit', 'CREATED_FILE')
    deleted_by_commit = RelationshipFrom('Commit', 'DELETED_FILE')
    renamed_by_commit = RelationshipFrom('Commit', 'RENAMED_FILE')
    permissions_changed_by_commit = RelationshipFrom('Commit', 'CHANGED_FILE_PERMISSIONS')
    content_changed_by_commit = RelationshipFrom('Commit', 'CHANGED_FILE_CONTENT')


class Actor(StructuredNode):
    name = StringProperty(required=True, alias='name')
    email = StringProperty(required=True)

    @staticmethod
    def from_git_actor(actor: git.Actor):
        return Actor.get_or_create(
            { 'name': actor.name, 'email': actor.email }
        )[0].save()


def get_closest_tag_info(commit: git.Commit):
    def desc(*args):
        return commit.repo.git.describe('--abbrev=0', *args, commit.hexsha)
    result = {
        'predecessors': {},
        'successors': {},
    }
    try:
        result['predecessors']['annotated_tag'] = desc()
    except git.GitCommandError:
        pass
    try:
        result['predecessors']['lightweight_tag'] = desc('--tags')
    except git.GitCommandError:
        pass
    # try:
    #     result['predecessors']['ref'] = desc('--all')
    # except git.GitCommandError:
    #     pass


    # try:
    #     result['successors']['ref'] = desc('--contains', '--all')
    # except git.GitCommandError:
    #     return result # if no ref exists we don't need to even ask the other ones
    # try:
    #     result['successors']['lightweight_tag'] = desc('--contains', '--tags')
    # except git.GitCommandError:
    #     return result # similarly if no lightweight tag exists we can stop
    # try:
    #     result['successors']['annotated_tag'] = desc('--contains')
    # except git.GitCommandError:
    #     pass

    return result


class Commit(StructuredNode):
    repo = StringProperty(unique_index=True, required=True)
    sha = StringProperty(unique_index=True, required=True)

    parents = RelationshipTo('Commit', 'PARENT')
    message = StringProperty()

    author: One = Relationship('Actor', 'AUTHOR', cardinality=One)
    authored_date = IntegerProperty() # unix timestamp UTC
    author_tz_offset = IntegerProperty() # timezone offset in seconds

    committer: One = Relationship('Actor', 'COMMITTER', cardinality=One)
    committed_date = IntegerProperty() # unix timestamp UTC
    committer_tz_offset = IntegerProperty() # timezone offset in seconds

    encoding = StringProperty()

    successfully_built = BooleanProperty()
    build_jdk_version = StringProperty()

    preceding_annotated_tag = RelationshipTo('Tag', 'PRECEDING_ANNOTATED_TAG')
    preceding_lightweight_tag = RelationshipTo('Tag', 'PRECEDING_LIGHTWEIGHT_TAG')
    # succeeding_annotated_tag = RelationshipTo('Tag', 'SUCCEEDING_ANNOTATED_TAG')
    # succeeding_lightweight_tag = RelationshipTo('Tag', 'SUCCEEDING_LIGHTWEIGHT_TAG')

    @staticmethod
    def from_git_commit(commit: git.Commit, limited=False):
        repo_name = os.path.basename(commit.repo.working_dir)
        neo_commit, *parents = Commit.get_or_create(
            { 'repo': repo_name, 'sha': commit.hexsha },
            *[{'repo': repo_name, 'sha': parent.hexsha} for parent in commit.parents]
        )

        author = Actor.from_git_actor(commit.author)
        committer = Actor.from_git_actor(commit.committer)

        neo_commit.message = commit.message
        if len(neo_commit.author) == 0:
            neo_commit.author.connect(author)
        else:
            assert neo_commit.author.single() == author
        neo_commit.authored_date = commit.authored_date
        neo_commit.author_tz_offset = commit.author_tz_offset
        if len(neo_commit.committer) == 0:
            neo_commit.committer.connect(committer)
        else:
            assert neo_commit.committer.single() == committer

        neo_commit.committed_date = commit.committed_date
        neo_commit.committer_tz_offset = commit.committer_tz_offset
        neo_commit.encoding = commit.encoding

        for parent in parents:
            neo_commit.parents.connect(parent)

        tag_info = get_closest_tag_info(commit)
        if 'annotated_tag' in tag_info['predecessors']:
            neo_commit.preceding_annotated_tag.connect(
                Tag.get_or_create({ 'tag': tag_info['predecessors']['annotated_tag'] })[0]
            )
        if 'lightweight_tag' in tag_info['predecessors']:
            neo_commit.preceding_lightweight_tag.connect(
                Tag.get_or_create({ 'tag': tag_info['predecessors']['lightweight_tag'] })[0]
            )
        # if 'annotated_tag' in tag_info['successors']:
        #     neo_commit.succeeding_annotated_tag.connect(
        #         Tag.get_or_create({ 'tag': tag_info['successors']['annotated_tag'] })[0]
        #     )
        # if 'lightweight_tag' in tag_info['successors']:
        #     neo_commit.succeeding_lightweight_tag.connect(
        #         Tag.get_or_create({ 'tag': tag_info['successors']['lightweight_tag'] })[0]
        #     )


        if limited:
            return neo_commit

        for parent in commit.parents:
            for modification in commit.diff(parent, create_patch=True):
                diff_text = modification.diff
                a_file = SourceFile.get_or_create(
                    { 'path': modification.a_path, 'mode': modification.a_mode }
                )[0] if modification.a_path else None
                b_file = SourceFile.get_or_create(
                    { 'path': modification.b_path }
                )[0] if modification.b_path else None

                if a_file == None and b_file != None:
                    b_file.created_by_commit.connect(neo_commit)
                    b_file.touched_by_commit.connect(neo_commit)
                elif a_file != None and b_file == None:
                    a_file.deleted_by_commit.connect(neo_commit)
                    a_file.touched_by_commit.connect(neo_commit)
                elif a_file == None and b_file == None:
                    raise Exception('Unknown file modification type: %s' % modification)
                else:
                        a_file.touched_by_commit.connect(neo_commit)
                        b_file.touched_by_commit.connect(neo_commit)

                        if a_file.path != b_file.path: # File renamed
                            a_file.renamed_by_commit.connect(neo_commit)
                            a_file.deleted_by_commit.connect(neo_commit)

                            b_file.created_by_commit.connect(neo_commit)

                            a_file.renamed_to.connect(b_file)

                        if modification.a_mode != modification.b_mode:
                            a_file.permissions_changed_by_commit.connect(neo_commit)
                            b_file.permissions_changed_by_commit.connect(neo_commit)
                            b_file.touched_by_commit.connect(neo_commit)


        return neo_commit

    @staticmethod
    def from_ref(repo: git.Repo, ref: str):
        return Commit.from_git_commit(repo.commit(ref))


class TagNamespace(StructuredNode):
    name = StringProperty(required=True, unique_index=True, alias='name')
    next_ns = RelationshipTo('TagNamespace', 'DOWN')
    referenced_tag = RelationshipTo('Tag', 'TAG')


class Tag(StructuredNode):
    tag = StringProperty(required=True, unique_index=True)
    commit = Relationship('Commit', 'COMMIT', cardinality=ZeroOrOne)

    # blob = Relationship('NeoBlob', 'BLOB', cardinality=ZeroOrOne)
    # tree = Relationship('NeoTree', 'TREE', cardinality=ZeroOrOne)

    referenced_tag = Relationship('Tag', 'REFERENCED_TAG', cardinality=ZeroOrOne)
    tagger = Relationship('Actor', 'TAGGER', cardinality=One)
    tagged_date = IntegerProperty() # unix timestamp UTC
    tagger_tz_offset = IntegerProperty() # timezone offset in seconds
    # object maybe? not sure yet
    message = StringProperty()

    @staticmethod
    def from_git_tag_reference(tag: git.TagReference):
        assert type(tag) is git.TagReference

        *tag_namespaces, tag_name = tag.name.split('/')

        neo_tag = Tag.get_or_create(
            { 'tag': tag.name },
        )[0]

        last_ns_link = neo_tag
        for namespace_index, tag_namespace in reversed(list(enumerate(tag_namespaces))):
            namespace_name = '/'.join(tag_namespaces[:namespace_index + 1])
            neo_tag_namespace = TagNamespace.get_or_create(
                { 'name': namespace_name }
            )[0]

            if type(last_ns_link) is Tag:
                neo_tag_namespace.referenced_tag.connect(last_ns_link)
            else:
                neo_tag_namespace.next_ns.connect(last_ns_link)
            last_ns_link = neo_tag_namespace

        if tag.tag:
            neo_tag.message = tag.tag.message
            neo_tag.tagged_date = tag.tag.tagged_date
            neo_tag.tagger_tz_offset = tag.tag.tagger_tz_offset

            tagger = Actor.from_git_actor(tag.tag.tagger)
            if len(neo_tag.tagger) == 0:
                neo_tag.tagger.connect(tagger)
            else:
                assert neo_tag.tagger.single() == tagger
            referenced_tag = Tag.from_git_tag_object(tag.tag)
            if len(neo_tag.referenced_tag) == 0:
                neo_tag.referenced_tag.connect(referenced_tag)
            else:
                assert neo_tag.referenced_tag.single() == referenced_tag

        if tag.commit:
            commit = Commit.from_ref(tag.repo, tag.commit.hexsha)
            if len(neo_tag.commit) == 0:
                neo_tag.commit.connect(commit)
            else:
                assert neo_tag.commit.single() == commit

        return neo_tag

    @staticmethod
    def from_git_tag_object(tag: git.TagObject):
        assert type(tag) is git.TagObject

        neo_tag = Tag.get_or_create(
            { 'tag': tag.tag },
        )[0]

        *tag_namespaces, tag_name = tag.tag.split('/')
        last_ns_link = neo_tag
        for namespace_index, tag_namespace in reversed(list(enumerate(tag_namespaces))):
            namespace_name = '/'.join(tag_namespaces[:namespace_index + 1])
            neo_tag_namespace = TagNamespace.get_or_create(
                { 'name': namespace_name }
            )[0]

            if type(last_ns_link) is Tag:
                neo_tag_namespace.referenced_tag.connect(last_ns_link)
            else:
                neo_tag_namespace.next_ns.connect(last_ns_link)
            last_ns_link = neo_tag_namespace

        neo_tag.message = tag.message
        neo_tag.tagged_date = tag.tagged_date
        neo_tag.tagger_tz_offset = tag.tagger_tz_offset

        tagger = Actor.from_git_actor(tag.tagger)
        if len(neo_tag.tagger) == 0:
            neo_tag.tagger.connect(tagger)
        else:
            assert neo_tag.tagger.single() == tagger

        if tag.object:
            if type(tag.object) is git.TagObject:
                referenced_tag = Tag.from_git_tag_object(tag.object)
                if len(neo_tag.referenced_tag) == 0:
                    neo_tag.referenced_tag.connect(referenced_tag)
                else:
                    assert neo_tag.referenced_tag.single() == referenced_tag
            elif type(tag.object) is git.Commit:
                commit = Commit.from_ref(tag.repo, tag.object.hexsha)
                if len(neo_tag.commit) == 0:
                    neo_tag.commit.connect(commit)
                else:
                    assert neo_tag.commit.single() == commit
            else:
                raise Exception('Unknown tag object type: %s' % type(tag.object))

        return neo_tag

    @staticmethod
    def from_ref(repo: git.Repo, ref):
        tag = repo.tag(ref)
        if type(tag) is git.TagObject:
            return Tag.from_git_tag_object(tag)
        elif type(tag) is git.TagReference:
            return Tag.from_git_tag_reference(tag)
        else:
            raise Exception('Unknown tag type: %s' % type(tag))

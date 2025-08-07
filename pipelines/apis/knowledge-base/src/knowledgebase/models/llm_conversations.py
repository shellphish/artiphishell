
import re
from datetime import datetime
from .git_repo import Commit
from ..node_update_hooks import node_updated
from neomodel import StructuredNode, StringProperty, IntegerProperty, RelationshipTo, RelationshipFrom, Relationship, ZeroOrMore, OneOrMore, One, DateProperty, DateTimeFormatProperty, JSONProperty, StructuredRel, ZeroOrOne, FloatProperty

        # TODO:
        # https://www.cloudbees.com/security-advisories/jenkins-security-advisory-2011-11-08
        # elif match := re.match(r'(http|https)://www.cloudbees.com/security-advisori/jenkins-security-advisory-(\d{4}-\d{2}-\d{2}).cb', url):
        #     # not relevant here, different advisory style/layout
        #     return None
        # elif match := re.match(r'(http|https)://www.cloudbees.com/jenkins-advisory/jenkins-security-advisory-(\d{4}-\d{2}-\d{2}).cb', url):
        #     # not relevant here, different advisory style/layout
        #     return None
class LLMParticipant(StructuredNode):
    name = StringProperty(unique_index=True, required=True)

class LLMRole(StructuredNode):
    name = StringProperty(unique_index=True, required=True)

class FunctionTool(StructuredNode):
    type = StringProperty(unique_index=True, required=True)
    tool_name = StringProperty(unique_index=True, required=True)
    # tool_id = StringProperty()
    description = StringProperty()
    parameters = JSONProperty()


class LLMToolCall(StructuredNode):
    tool_name = StringProperty(required=True)
    tool_type = StringProperty(required=True)
    args = JSONProperty(required=True)
    function_tool = RelationshipTo('FunctionTool', 'TOOL')
    # output = RelationshipTo('FunctionToolCallOutput', 'OUTPUT')

class LLMToolCallInstance(StructuredNode):
    tool_call_id = StringProperty(unique_index=True, required=True)
    request_date = DateTimeFormatProperty(format='%Y-%m-%d %H:%M:%S')
    response_date = DateTimeFormatProperty(format='%Y-%m-%d %H:%M:%S')
    tool_call = RelationshipTo('LLMToolCall', 'INSTANCE_OF')
    request = RelationshipTo('LLMMessage', 'REQUEST')
    response = RelationshipTo('LLMMessage', 'RESPONSE')

class LLMMessageInConversation(StructuredRel):
    index_in_conversation = IntegerProperty()
    date = DateTimeFormatProperty(default_now=True, format='%Y-%m-%d %H:%M:%S')

class LLMToolCallInMessage(StructuredRel):
    index_in_message = IntegerProperty()

class LLMPromptTemplate(StructuredNode):
    template_string = StringProperty(unique_index=True, required=True)

class LLMPromptTemplateInstantiation(StructuredRel):
    prompt_args = JSONProperty()

class LLMMessage(StructuredNode):
    content = StringProperty(required=True, unique_index=True)
    author = RelationshipTo('LLMParticipant', 'AUTHOR')
    role = RelationshipTo('LLMRole', 'ROLE')
    origin = RelationshipTo('LLMOrigin', 'ORIGIN')
    prompt_template = RelationshipTo('LLMPromptTemplate', 'INSTANCE_OF', model=LLMPromptTemplateInstantiation)
    tool_calls = RelationshipTo('LLMToolCall', 'TOOL_CALL', model=LLMToolCallInMessage)
    available_tools = RelationshipTo('FunctionTool', 'AVAILABLE_TOOL')
    response_to = RelationshipTo('LLMMessage', 'RESPONSE_TO')

class LLMOrigin(StructuredNode):
    # The origin of the conversation: e.g. gpt_preprocessing, derive_patch, etc.
    origin = StringProperty(unique_index=True, required=True)


class LLMMessageInContext(StructuredRel):
    index_in_conversation = IntegerProperty()


class LLMMessageIsResponse(StructuredRel):
    result_index = IntegerProperty()


class LLMCompletionRequest(StructuredNode):
    # not the same uuid as LLMConversation, each API request must create a unique LLM completion
    uuid = StringProperty(unique_index=True, required=True)
    requested_model = StringProperty(required=True)
    temperature = FloatProperty()
    model_participant = RelationshipTo('LLMParticipant', 'MODEL_PARTICIPANT')
    context_messages = RelationshipTo('LLMMessage', 'CONTEXT_MESSAGE', model=LLMMessageInContext)
    conversation = RelationshipTo('LLMConversation', 'IN_CONVERSATION')
    response_message = RelationshipTo('LLMMessage', 'RESPONSE_MESSAGE', model=LLMMessageIsResponse)


class LLMConversation(StructuredNode):
    uuid = StringProperty(unique_index=True, required=True)
    start_date = DateTimeFormatProperty(default_now=True, format='%Y-%m-%d %H:%M:%S')
    origin = RelationshipTo('LLMOrigin', 'ORIGIN')
    participants = RelationshipTo('LLMParticipant', 'PARTICIPANT')
    messages = RelationshipTo('LLMMessage', 'MESSAGE', model=LLMMessageInConversation)
    prompt_templates = RelationshipTo('LLMPromptTemplate', 'USES_PROMPT_TEMPLATE', model=LLMPromptTemplateInstantiation)
    available_tools = RelationshipTo('FunctionTool', 'AVAILABLE_TOOL')
    tool_calls = RelationshipTo('LLMToolCall', 'TOOL_CALL', model=LLMToolCallInMessage)

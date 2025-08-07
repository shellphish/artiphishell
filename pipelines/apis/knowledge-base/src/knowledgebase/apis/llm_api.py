
## Message we get from components
INITIAL_PROMPT = """
# TASK
You are an interactive reverse-engineering and vulnerability patching assistant. Using the given `tool`s, you will be asked to patch a vulnerable function (called VULNFUNCTION). The patch should be minimal and produce the full newly patched function (PATCHFUNCTION). You must ensure that the existing semantics of PATCHFUNCTION, including any subroutines and methods it calls and the values it returns, are preserved. The semantics of PATCHFUNCTION and VULNFUNCTION must be the same for all non-bug-triggering inputs.
If there are multiple instances of the described vulnerability in VULNFUNCTION, you must patch all of them.
If your patch is accepted, you will be rewarded with a flag.

# TOOL USAGE RULES
Before using one of the available `tool`s, first describe why you are calling the `tool` and what you expect it to do and what information you will use from the result. Make sure to retrieve all available information about VULNFUNCTION and its callers/callees before proposing a patch.
When calling any `tool`, ensure that your arguments are escaped properly and formatted to be parsed as json fields.
When calling any `tool`, the function arguments must not contain orphan escape characters or other problematic characters.

# RESOURCE LIMITS
You have a total of 10 steps to complete your task.

# VULNERABILITY REPORT
You have been provided with the following vulnerability report:

```
{REPORT}
```

The source code of the vulnerable function is:
```
{VULNFUNCTION}
```
"""
"""
' {
      "cur_message_id": 1,
      "requested_model": "GPT4",
      "origin": "derive_patch",
      "chat_id": None,

      "messages": [
        {
          "role": "system",
          "message_id": 1,
          "tool_calls": [{}],
          "author": "derive_path.allfunctions",
          prompt_template: INITIAL_PROMPT,
          prompt_args: {
            "VULNFUNCTION": "somefunction()",
            "vuln_description": "fix this guy"
          }
          }

        },

      ],
    }
'
"""

from flask import Flask, request, jsonify
import hashlib
import uuid
from jinja2 import StrictUndefined, Template
from datetime import datetime
import json
import os
# from models.llm_conversations import LLMConversation, LLMMessage, LLMParticipant, LLMOrigin, LLMPromptTemplate, LLMCompletionRequest, LLMMessageInConversation
from litellm import completion

# os.environ["NEO4J_URL"] = "bolt://neo4j:!!Shellphish!!@beatty.unfiltered.seclab.cs.ucsb.edu:7688"
from ..settings import *
from ..models.llm_conversations import LLMConversation, LLMMessage, LLMParticipant, LLMOrigin, LLMPromptTemplate, LLMCompletionRequest, LLMMessageInConversation, FunctionTool, LLMRole, LLMToolCall, LLMToolCallInMessage, LLMToolCallInstance


#os.environ["OPENAI_API_KEY"]
app = Flask(__name__)
def log_completion_response(origin, chat_id, response, resp_message_id, completion_request, message_objects):
    """
    Sample response:
    ModelResponse(id='chatcmpl-9FSQGVos47TkwBbPbNlocKxkuPpya',
                choices=[Choices(finish_reason='tool_calls',
                                index=0,
                                message=Message(content=None,
                                                role='assistant',
                                                tool_calls=[
                                                            ChatCompletionMessageToolCall(function=Function(arguments='{"name": "handle_AUTH"}', name='get_referencing_functions'), id='call_FSDW6xP4IaeG25f8dgEG24qs', type='function'),
                                                            ChatCompletionMessageToolCall(function=Function(arguments='{"name": "handle_AUTH"}', name='get_referenced_functions'), id='call_cqlcllaF6zuHNfEHmMFf4CjQ', type='function')
                                                            ]
                                                )
                                )
                        ],
                created=1713471204,
                model='gpt-4-1106-preview',
                object='chat.completion',
                system_fingerprint='fp_b128be01d8',
                usage=Usage(completion_tokens=49, prompt_tokens=4278, total_tokens=4327))
    """
    kb_conversation = LLMConversation.get_or_create({'uuid': chat_id})[0]
    kb_origin = LLMOrigin.get_or_create({'origin': origin})[0]
    kb_conversation.origin.connect(kb_origin)

    # this is the author of response (it is the model)
    author = response.get("model")

    kb_author = LLMParticipant.get_or_create({'name': author})[0]
    # model can output multiple responses
    # message sent back to the user
    response_choices = []
    # we can have multiple responses, we need to keep track of all of them.
    choices = response.get("choices")

    # for returning purposes
    response_dict = {"choices": []}
    for choice in choices:
        resp_finish_reason = choice.get("finish_reason")
        resp_index = choice.get("index")
        resp_message = choice.get("message")
        resp_content  = resp_message.get("content", '')
        resp_role = resp_message.get("role")

        choice_dict= {"finish_reason": resp_finish_reason,
                      "index": resp_index,
                      "message": {}}

        choice_dict["message"]["content"] = resp_content
        choice_dict["message"]["role"] = resp_role
        choice_dict["message"]["author"] = author
        choice_dict["message"]["tool_calls"] = []
        choice_dict["message"]["message_id"] = resp_message_id

        tool_calls = resp_message.get("tool_calls", [])
        if not resp_content:
            resp_content = str(resp_message)
        kb_message = LLMMessage.get_or_create({'content': resp_content})[0]

        for req_message_object in message_objects:
            kb_message.response_to.connect(req_message_object)

        if tool_calls:
            # iterating over toolcalls
            for tool_call in tool_calls:
                tool_call = dict(tool_call)
                tool_call_id = tool_call['id']
                tool_type = tool_call['type']
                tool_function = dict(tool_call['function'])
                arguments = tool_function['arguments']
                tool_name = tool_function['name']

                kb_tool_call = LLMToolCall.get_or_create({
                    'tool_name': tool_name,
                    'tool_type': tool_type,
                    'args': arguments
                })[0]
                kb_tool_call_instance = LLMToolCallInstance.get_or_create({'tool_call_id': tool_call_id})[0]
                if kb_tool_call_instance.request_date is None:
                    kb_tool_call_instance.request_date = datetime.now()
                if kb_tool_call_instance.response_date is None:
                    kb_tool_call_instance.response_date = datetime.now()
                kb_tool_call_instance.request.connect(kb_message)
                kb_tool_call_instance.tool_call.connect(kb_tool_call)

                tool_functions = FunctionTool.get_or_create({'tool_name': tool_name,
                                                             'type': tool_type,
                                                             })[0]
                kb_tool_call.function_tool.connect(tool_functions)
                kb_tool_call.save()
                #kb_function_tool = FunctionTool.get_or_create({'tool_name': tool_name})[0]
                #kb_tool_call.output.connect(LLMMessage.get_or_create({'content': tool_call['output']})[0])
                kb_conversation.tool_calls.connect(kb_tool_call)
                kb_message.tool_calls.connect(kb_tool_call, {"result_index": resp_message_id})
                kb_conversation.messages.connect(kb_message, {"index_in_conversation": resp_message_id})

                # for response message
                tool_call_dict = {}
                resp_id = tool_call['id']
                tool_call_dict['id'] = resp_id
                tool_call_dict['type'] = tool_type
                tool_call_dict["function"] = {}
                tool_call_dict["function"]= json.loads(json.dumps(tool_function))
                #tool_call_dict["function"]["arguments"] = str(tool_function['arguments'])
                choice_dict["message"]["tool_calls"].append(tool_call_dict)

        response_dict["choices"].append(choice_dict)
        kb_conversation.participants.connect(kb_author)
        kb_conversation.save()
        kb_message.author.connect(kb_author)
        kb_message.origin.connect(kb_origin)
        kb_message.save()
        # appending response message
        response_choices.append(dict(choice))
        completion_request.response_message.connect(kb_message, {"result_index": resp_message_id})
        completion_request.save()

    response_dict["chat_id"] = chat_id
    response_dict["origin"] = origin
    response_dict["model"] = author
    return response_dict





# def log_completion_assistant(origin, chat_id, response, resp_message_id, completion_request, message_objects):
#     pass
#
# def log_completion_tool(origin, chat_id, response, resp_message_id, completion_request, message_objects):
#     pass
#
# def log_completion_system(message, message_id, completion_request):
#     prompt_template = message.pop('prompt_template')
#     prompt_args = message.pop('prompt_args', {})
#     content = message.pop('content', "")
#     tool_calls = message.pop('tool_calls', [])


def log_completion_request(origin, chat_id, messages, requested_model, temperature=None, tools=[]):
    kb_conversation = LLMConversation.get_or_create({'uuid': chat_id})[0]
    """
    origin tracks why the conversation happened.
    In which context does the conversation live.
    Each component has its own context.
    """
    kb_origin = LLMOrigin.get_or_create({'origin': origin})[0]

    kb_conversation.origin.connect(kb_origin)
    completion_request_dict = {}
    new_messages = []
    message_objects = []
    message_ids = []
    # messages is a list of dictionaries
    completion_request = LLMCompletionRequest.get_or_create({
        'uuid': str(uuid.uuid4()),
        "requested_model": requested_model,
        # "message_ids": message_ids
    })[0]
    if temperature is not None:
        completion_request.temperature = temperature

    """
    First we deal with tools, these tools are provided by component.
    NOTE: these are not response from LLM, rather its the option of responses that LLM can choose from
    """
    for function_tool in tools:
        tool_type = function_tool['type']
        tool_function = function_tool['function']
        tool_name = tool_function['name']
        tool_description = tool_function['description']
        tool_parameters = tool_function['parameters']

        assert set(function_tool.keys()) == {'type', 'function'} and set(tool_function.keys()) == {'name',
                                                                                                   'description',
                                                                                                   'parameters'}
        tool_functions = FunctionTool.get_or_create({
            'type': tool_type,
            'tool_name': tool_name,
            'description': tool_description,
            'parameters': tool_parameters,
        })[0]
        kb_conversation.available_tools.connect(tool_functions)
        # kb_message.available_tools.connect(tool_functions)
    print("done with tools")

    # second we deal with messages
    for message in messages:
        # extract all keys from message
        role = message.pop('role')
        author = message.pop('author', "")
        assert author
        message_id = message.pop('message_id')
        # tool_calls = message.pop('tool_call', [])
        if role == "system" or role == "user":
            print("starting with system")

            # This is a system message, we need to handle it differently
            prompt_template = message.pop('prompt_template', None)
            prompt_args = message.pop('prompt_args', None)
            kb_content = message.pop('content', "")
            #tool_calls = message.pop('tool_calls', [])
            # we're done with the message now, we can redefine it. make sure we've handled all the keys
            assert not message, f"Unknown keys in message: {message.keys()}"
            # if the prompt args and template are present, we need to render the template with the prompt args and create content
            if prompt_args is not None or prompt_template is not None:
                assert prompt_args is not None and prompt_template is not None, "Both prompt_args and prompt_template must be provided"
                template = Template(prompt_template, undefined=StrictUndefined)
                assert not kb_content, "Content must not be provided if prompt_args and prompt_template are provided"
                kb_content = template.render(prompt_args)
                print(f"kb_content: {kb_content} after rendering {template!r} with {prompt_args!r}")

            assert kb_content, "Content must be provided if role is system"
            kb_message = LLMMessage.get_or_create({'content': kb_content})[0]
            kb_role = LLMRole.get_or_create({'name': role})[0]
            kb_message.role.connect(kb_role)
            kb_author = LLMParticipant.get_or_create({'name': author})[0]
            kb_conversation.messages.connect(kb_message, {"index_in_conversation": message_id})
            kb_conversation.participants.connect(kb_author)
            kb_message.author.connect(kb_author)
            kb_message.origin.connect(kb_origin)
            if prompt_args:
                kb_template = LLMPromptTemplate.get_or_create({"template_string": prompt_template})[0]
                kb_message.prompt_template.connect(kb_template, {'prompt_args': prompt_args})
                kb_conversation.prompt_templates.connect(kb_template, {'prompt_args': prompt_args})
            completion_request.context_messages.connect(kb_message, {"index_in_conversation": message_id})
            # saving message objects because we need to connect tool calls to context
            message_objects.append(kb_message)
            new_message = {"role": role, "content": kb_content}
            new_messages.append(new_message)

        elif role == "assistant":
            print("starting with assistant")
            """
            It looks something like this
            {'content': None,
           'role': 'assistant',
           'tool_calls': [{'id': 'call_xeWkG4bWjOncVYRSSWkBwih6',
             'type': 'function',
             'function': {'arguments': '{"function_identifier":"handle_AUTH"}',
              'name': 'get_function_source'}}],
           'message_id': 1},
            """
            print("starting with assistant")

            ## assistant has content as null, but it will always have tool calls
            content = message.pop('content', "")

            tool_calls = message.pop('tool_calls', [])

            if not content:
                kb_content = str(tool_calls)
            else:
                kb_content = content
            kb_message = LLMMessage.get_or_create({'content': kb_content})[0]
            kb_role = LLMRole.get_or_create({'name': role})[0]
            kb_author = LLMParticipant.get_or_create({'name': author})[0]
            kb_conversation.messages.connect(kb_message, {"index_in_conversation": message_id})
            kb_conversation.participants.connect(kb_author)
            kb_message.author.connect(kb_author)
            kb_message.role.connect(kb_role)
            kb_message.origin.connect(kb_origin)

            for tool_call in tool_calls:
                tool_call = dict(tool_call)
                tool_type = tool_call['type']
                tool_function = dict(tool_call['function'])
                arguments = tool_function['arguments']
                tool_name = tool_function['name']

                kb_tool_call = LLMToolCall.get_or_create({'tool_name': tool_name,
                                                          'tool_type': tool_type,
                                                          'args': arguments})[0]
                tool_functions = FunctionTool.get_or_create({'tool_name': tool_name,
                                                             'type': tool_type,
                                                             })[0]
                kb_tool_call_instance = LLMToolCallInstance.get_or_create(
                    {'tool_call_id': tool_call['id']},
                )[0]
                if kb_tool_call_instance.request_date is None:
                    kb_tool_call_instance.request_date = datetime.now()
                kb_tool_call_instance.tool_call.connect(kb_tool_call)
                kb_tool_call_instance.request.connect(kb_message)

                kb_tool_call.function_tool.connect(tool_functions)
                # kb_function_tool = FunctionTool.get_or_create({'tool_name': tool_name})[0]
                # kb_tool_call.output.connect(LLMMessage.get_or_create({'content': tool_call['output']})[0])
                kb_conversation.tool_calls.connect(kb_tool_call)
                kb_message.tool_calls.connect(kb_tool_call, {"index_in_message": message_id})

                #kb_conversation.messages.connect(kb_message, {"index_in_conversation": message_id})
            kb_conversation.messages.connect(kb_message, {"index_in_conversation": message_id})
            # checking if prompt template is present
            message_objects.append(kb_message)
            if tool_calls:
                new_message = {"role": role, "content": content, "tool_calls": tool_calls}
            else:
                new_message = {"role": role, "content": kb_content}
            new_messages.append(new_message)

        elif role == "tool":
            print("starting with tool")
            """
            It looks something like this:
            {'role': 'tool',
               'tool_call_id': 'call_xeWkG4bWjOncVYRSSWkBwih6',
               'name': 'get_function_source',
               'content': '# TOOL RETURNED SUCCESS\n\n{\n  "call": {\n    "function": "get_function_source",\n    "arguments": {\n      "function_identifier": "handle_AUTH"\n    }\n  },\n  "result": "int handle_AUTH( int fd, char *line )\\n{\\n\\tchar *user;\\n\\tint ul = 0;\\n\\tchar *pass;\\n\\tint pl = 0;\\n\\tint perms = 0;\\n\\tchar *t = NULL;\\n\\tchar response[256];\\n\\tunsigned char *decode;\\n\\n\\tif ( line == NULL ) {\\n\\t\\treturn 0;\\n\\t}\\n\\n\\tif ( strncasecmp( line, \\"PLAIN\\", 5) == 0 ) {\\n\\t\\tt = local_strstr( line, \\" \\" );\\n\\n\\t\\tif ( t == NULL ) {\\n\\t\\t\\twrite_wrapper( fd, \\"334\\\\n\\", 4 );\\n\\n\\t\\t\\tif ( readuntil( fd, response, 256, \'\\\\n\') <= 0 ) {\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tdecode_b64( (unsigned char *)response, &decode );\\n\\n\\t\\t\\tif ( decode == NULL ) {\\n\\t\\t\\t\\tsend_string(fd, \\"579 Failed to decode\\\\n\\");\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tul = local_strlen( (const char *)decode );\\n\\n\\t\\t\\tif ( ul >= 256 ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"598 Too long\\\\n\\", 13);\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tuser = strdup( (const char *)decode );\\n\\n\\t\\t\\tif ( user == NULL ) {\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tpl = local_strlen( (const char *)(decode + ul + 1) );\\n\\n\\t\\t\\tif ( pl >= 256 ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"598 Too long\\\\n\\", 13);\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(user);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tpass = strdup( (const char *)(decode + ul + 1));\\n\\n\\t\\t\\tif ( pass == NULL ) {\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(user);\\n\\t\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tmemcpy( client_data.authd_user, user, sizeof(client_data.authd_user));\\n\\n\\t\\t\\tif ( check_user_pass( user, pass, &perms) ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"250 Auth Success\\\\n\\", 17);\\n\\t\\t\\t\\tclient_data.authd = perms;\\n\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(pass);\\n\\t\\t\\t\\treturn 1;\\n\\t\\t\\t} else {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"250 Auth Failed\\\\n\\", 16);\\n\\t\\t\\t\\tmemset( client_data.authd_user, 0, sizeof(client_data.authd_user) );\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(user);\\n\\t\\t\\t\\tfree(pass);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tfree(decode);\\n\\t\\t\\tfree(user);\\n\\t\\t\\tfree(pass);\\n\\t\\t} else {\\n\\t\\t\\tdecode_b64( (unsigned char *)(t+1), &decode);\\n\\n\\t\\t\\tif ( decode == NULL ) {\\n\\t\\t\\t\\tsend_string(fd, \\"580 Failed to decode user\\\\n\\");\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tul = local_strlen( (const char *)decode );\\n\\n\\t\\t\\tif ( ul >= 256 ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"598 Too long\\\\n\\", 13);\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tuser = strdup( (const char *)decode );\\n\\n\\t\\t\\tif ( user == NULL ) {\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tpl = local_strlen( (const char *)(decode +ul + 1));\\n\\n\\t\\t\\tif ( pl >= 256 ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"598 Too long\\\\n\\", 13);\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tpass = strdup( (const char *)(decode + ul + 1) );\\n\\n\\t\\t\\tif ( pass == NULL ) {\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(user);\\n\\t\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\n\\t\\t\\tmemcpy( client_data.authd_user, user, sizeof(client_data.authd_user));\\n\\n\\t\\t\\tif ( check_user_pass( user, pass, &perms) ) {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"250 Auth Success\\\\n\\", 17);\\n\\n\\t\\t\\t\\tclient_data.authd = perms;\\n\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(pass);\\n\\t\\t\\t\\treturn 1;\\n\\t\\t\\t} else {\\n\\t\\t\\t\\twrite_wrapper(fd, \\"250 Auth Failed\\\\n\\", 16);\\n\\t\\t\\t\\tmemset( client_data.authd_user, 0, sizeof(client_data.authd_user) );\\n\\t\\t\\t\\tfree(decode);\\n\\t\\t\\t\\tfree(user);\\n\\t\\t\\t\\tfree(pass);\\n\\t\\t\\t\\treturn 0;\\n\\t\\t\\t}\\n\\t\\t\\tfree(decode);\\n\\t\\t\\tfree(user);\\n\\t\\t\\tfree(pass);\\n\\t\\t}\\n\\t} else if ( strcasecmp( line, \\"LOGIN\\") == 0 ) {\\n\\t\\twrite_wrapper( fd, \\"334 VXNlcm5hbWU6\\\\n\\", 17 );\\n\\n\\t\\tmemset( response, 0, 256 );\\n\\n\\t\\tif ( readuntil( fd, response, 256, \'\\\\n\') <= 0 ) {\\n\\t\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\tdecode_b64( (unsigned char *)response, &decode);\\n\\n\\t\\tif ( decode == NULL ) {\\n\\t\\t\\tsend_string(fd, \\"582 Failed to decode user\\\\n\\");\\n\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\tuser = strdup( (const char *)decode );\\n\\t\\tfree(decode);\\n\\n\\t\\tif ( user == NULL ) {\\n\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\twrite_wrapper( fd, \\"334 UGFzc3dvcmQ6\\\\n\\", 17 );\\n\\t\\t\\n\\t\\tmemset( response, 0, 256 );\\n\\n\\t\\tif ( readuntil( fd, response, 256, \'\\\\n\') <= 0 ) {\\n\\t\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\tdecode_b64( (unsigned char *)response, &decode);\\n\\n\\t\\tif ( decode == NULL ) {\\n\\t\\t\\tsend_string(fd, \\"583 Failed to decode pass\\\\n\\");\\n\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\tpass = strdup( (const char *)decode );\\n\\t\\tfree(decode);\\n\\n\\t\\tif ( pass == NULL ) {\\n\\t\\t\\twrite_wrapper(fd, \\"583 Error\\\\n\\", 10);\\n\\t\\t\\treturn 0;\\n\\t\\t}\\n\\n\\t\\tmemcpy( client_data.authd_user, user, local_strlen(user));\\n\\n\\t\\tif ( check_user_pass( user, pass, &perms) ) {\\n\\t\\t\\twrite_wrapper(fd, \\"250 Auth Success\\\\n\\", 17);\\n\\t\\t\\tclient_data.authd = perms;\\n\\n\\t\\t\\tfree(user);\\n\\t\\t\\treturn 1;\\n\\t\\t} else {\\n\\t\\t\\twrite_wrapper(fd, \\"251 Auth Failed\\\\n\\", 16);\\n\\t\\t\\tmemset( client_data.authd_user, 0, sizeof(client_data.authd_user) );\\n\\t\\t\\tfree(user);\\n\\t\\t\\tfree(pass);\\n\\t\\t\\treturn 0;\\n\\t\\t}\\n\\t} else {\\n\\t\\twrite_wrapper( fd, \\"519 Invalid Auth\\\\n\\", 17);\\n\\t}\\n\\n\\treturn 0;\\n}"\n}',
               'message_id': 2}
            """
            print("starting with tool")

            tool_call_id = message.pop('tool_call_id')
            tool_name = message.pop('name')
            resp_content = message.pop('content', "")

            kb_message = LLMMessage.get_or_create({'content': resp_content})[0]
            kb_role = LLMRole.get_or_create({'name': role})[0]
            kb_author = LLMParticipant.get_or_create({'name': author})[0]
            kb_message.role.connect(kb_role)
            kb_tool_call_instance = LLMToolCallInstance.get_or_create({'tool_call_id': tool_call_id})[0]
            if kb_tool_call_instance.response_date is None:
                kb_tool_call_instance.response_date = datetime.now()
            kb_tool_call_instance.response.connect(kb_message)
            kb_conversation.messages.connect(kb_message, {"index_in_conversation": message_id})
            kb_conversation.participants.connect(kb_author)
            kb_message.author.connect(kb_author)
            kb_message.origin.connect(kb_origin)
            # kb_message.tool_calls.connect(kb_tool_call, {"index_in_message": message_id})
            completion_request.context_messages.connect(kb_message, {"index_in_conversation": message_id})
            message_objects.append(kb_message)
            new_message = {"role": role,
                           "tool_call_id": tool_call_id,
                           "name": tool_name,
                           "content": resp_content}
            new_messages.append(new_message)
        else:
            assert False, f"Unknown role: {role}"


        # if tool_calls:
        #     new_message["tool_calls"] = tool_calls

        completion_request.conversation.connect(kb_conversation)
        """
        TODO: link tool call results to toolcall objects
        """


    """
    completion request, we have an object everytime we made request, that keeps a track of context.
    We always create a mew uuid for each request.
    """
    return new_messages, tools, completion_request, message_objects


@app.route('/completions', methods=['POST'])
def query_llm():
    try:
        """
        High level structure of response
        """
        # it will be an array of messages
        ## we need to keep a track of which messageID lead to what responseID.
        ### add another field called message_ids in the query_llm request, which will be an array of message_ids.
        data = request.get_json()

        response_message_id = data.pop('response_message_id')
        # secret token
        secret_token = data.pop('secret_key')

        # Check secret token to make sure non one else is using our OPENAI key
        ## secret should be !!Shellphish!!
        hash = hashlib.sha256(secret_token.encode('utf-8')).hexdigest()
        if hash != "17b32a862c00b8c82c10f28e6733a93b642d07ed80e5041b2cfb005297c33edc":
            return jsonify({"error": "Invalid secret token"})

        # type of LLM
        requested_model = data.pop('requested_model')

        # origin is the component
        origin = data.pop('origin')
        # unique chat ID to keep the conversation going and keep the track of conversation
        chat_id = data.get('chat_id', None)

        # which message ids lead to generation of this prompt
        messages = data.get('messages', [])
        temperature = data.get('temperature', None)
        tools = data.get('tools', [])
        # If chatID does not exist, create a new one
        if not chat_id:
            chat_id = str(uuid.uuid4())
        else:
            chat_id = str(chat_id)
        # Logging the completion request
        completion_message, completion_tools, completion_request, message_objects = log_completion_request(origin, chat_id, messages, requested_model, temperature=temperature, tools=tools)
        # Query the LLM
        print("sending input to model")
        if completion_tools:
            response = completion(messages=completion_message, model=requested_model, tools=completion_tools)
        else:
            response = completion(messages=completion_message, model=requested_model)
        print("generating response message")
        # converting litellm.utils.ModelResponse to dict
        llm_response = dict(response)
        res_message = log_completion_response(origin, chat_id, llm_response, response_message_id, completion_request, message_objects)
        return jsonify(res_message)

    except Exception as e:
        import traceback

        return jsonify({"error": str(e), "traceback": str(traceback.format_exc())})

def main():
    app.run('0.0.0.0', debug=True)

if __name__ == "__main__":
    main()

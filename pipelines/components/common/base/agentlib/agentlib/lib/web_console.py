import os
import time
import json
from uuid import UUID
from typing import Any, Dict, List
from typing import Optional, Any, Dict, List, Union, Literal
from pathlib import Path

from langchain_core import output_parsers
from langchain.agents import AgentExecutor
from langchain_core.runnables import (
    RunnableSequence, AddableDict,
    RunnableAssign, RunnableParallel,
    RunnableLambda
)
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.load.serializable import Serializable
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.messages import BaseMessage, AIMessage, AIMessageChunk
from langchain.agents.output_parsers.openai_tools import OpenAIToolAgentAction
from flask import Flask, request, jsonify, send_from_directory, send_file

from .agents.agent import Agent, ChildAgent
from .agents.planning import AgentPlan
from .common.object import LocalObject, SaveLoadObject, CAN_SAVE_OBJECTS
from .common.parsers import BaseParser
from .common.base import LangChainLogger
from .common.store import LocalObjectRepository
from .common.code import Code


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)
# Set static folder
app.static_folder = os.path.join('../static')

CWD = os.getcwd()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/plan/<pid>/reset_to_step/<int:step>', methods=['POST'])
def reset_to_step(pid:str, step:int):
    plan = AgentPlan.get_by_id(pid)
    plan.reset_to_step(step)
    plan.save()
    return jsonify(dict(success=True))

@app.route('/api/session/<name>/tree')
def get_session_tree(name):
    session = RecordSession.get(name)
    tree = session.get_as_full_tree()
    return jsonify(tree) 

class UserRequest(LocalObject):
    pass

class UserAlert(UserRequest):
    body: Optional[str] = None

class UserConfirm(UserAlert):
    confirmed: Optional[bool] = None

class RecordRepository(LocalObjectRepository):
    __ROOT_DIR__ = Path('volumes/records').resolve()

class ConsoleRecord(LocalObject):
    __REPO__ = RecordRepository('console')

class LangChainRecord(ConsoleRecord):
    parent_record_id : Optional[str] = ConsoleRecord.Weak()
    child_record_ids: List[str] = []
    input: Optional[Any] = None
    output : Optional[Any] = None

    def add_child(self, child: ConsoleRecord):
        self.child_record_ids.append(child.id)
        if isinstance(child, LangChainRecord):
            child.parent_record_id = self.id

class LangChainClassRecord(LangChainRecord):
    class_name: Optional[str] = None

class UnknownRecord(LangChainClassRecord):
    pass

class SequenceRecord(LangChainClassRecord):
    pass

class LLMInvocationRecord(LangChainRecord):
    model: Optional[str] = None
    args: Optional[Dict[str, Any]] = None

class ToolExecutorRecord(LangChainClassRecord):
    pass

class ToolCallRecord(LangChainClassRecord):
    tool: Any

class ChatPromptTemplateRecord(LangChainClassRecord):
    input_variables: Optional[list[Any]] = None
    messages: Optional[List[Any]]

class OutputParserRecord(LangChainClassRecord):
    pass

class AgentAnnotationRecord(LangChainClassRecord):
    annotation: str
    severity: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None

class AgentRecord(LangChainClassRecord):
    agent_id : str = Agent.Weak()
    parent_agent_id : Optional[str] = Agent.Weak()


class RecordSession(LocalObject):
    name : str
    top_level_agents : List[str] = []
    other: List[str] = []

    def get_user_response(self, alert: UserAlert) -> UserAlert:
        # TODO send to the user
        if isinstance(alert, UserConfirm):
            alert.confirmed = True
        self.warn(f'Nothing can stop the AI Overlord from running the command: {alert.body}')
        #time.sleep(10)
        return alert
    
    def add_record(self, record: ConsoleRecord):

        # Find the top agents
        if isinstance(record, AgentRecord):
            if not record.parent_agent_id:
                self.top_level_agents.append(record.id)
            else:
                pass # This is already handled by the parent agent
        elif isinstance(record, LangChainRecord):
            if not record.parent_record_id:
                self.other.append(record.id)
        else:
            self.other.append(record.id)

    def get_as_full_tree(self, record:ConsoleRecord=None) -> list[dict]:
        if record is None:
            return [
                self.get_as_full_tree(record=ConsoleRecord.get_by_id(id))
                for id in self.top_level_agents
            ]

        out = dict(
            name = record.get_class_name(),
            id = record.id,
            data = SaveLoadObject._jsonify_all_fields(
                record.to_json(force_json=True).get('kwargs', {}),
                force_json=True
            )
        )

        if isinstance(record, LangChainRecord):
            children = []
            for id in record.child_record_ids:
                #print(f'Getting child {id}')
                res = self.get_as_full_tree(record=ConsoleRecord.get_by_id(id))
                if res:
                    children.append(res)

            children = [c for c in children if c]

            if len(children) > 0:
                out['children'] = children
            else:
                if isinstance(record, UnknownRecord):
                    return None

        return out
        
    @classmethod
    def get_file_path(cls, name):
        if CAN_SAVE_OBJECTS:
            os.makedirs('volumes/sessions', exist_ok=True)
        path = os.path.join('volumes/sessions', f'{name}.json')
        return path

    @classmethod
    def get(cls, name):
        path = cls.get_file_path(name)
        if os.path.exists(path):
            return cls.from_file(path)
        else:
            return cls(name=name)
    
    def save(self):
        self.save_to_path(
            self.get_file_path(self.name),
        )
        

def get_text_content(message, include_tools=False):
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        return "\n".join(
            m for m in map(
                lambda x: get_text_content(x, include_tools),
                message
            ) if m
        )
    if isinstance(message, dict):
        msg_type = message.get('type', 'text')
        if include_tools and msg_type == 'tool_use':
            return json.dumps(message, indent=2)
        if msg_type != 'text':
            return None
        if not message.get('text'):
            return None
        return message['text']
    return None


class WebConsoleLogger(LangChainLogger):
    class CurrentChain(LangChainLogger.CurrentChain):
        def __init__(self, *args, record: LangChainRecord=None, **kw):
            super().__init__(*args, **kw)
            self.current_record = record

        def save(self):
            if not self.current_record:
                return
            self.current_record.save()

    class CurrentLLMCall(LangChainLogger.CurrentLLMCall):
        def __init__(self, *args, record: LLMInvocationRecord=None, **kw):
            super().__init__(*args, **kw)
            self.current_record = record

        def save(self):
            if not self.current_record:
                return
            self.current_record.save()
    
    class CurrentTool(LangChainLogger.CurrentTool):
        def __init__(self, *args, record: ToolCallRecord=None, **kw):
            super().__init__(*args, **kw)
            self.current_record = record

        def save(self):
            if not self.current_record:
                return
            self.current_record.save()

    def __init__(self, **kw):
        super().__init__(**kw)
        self.current_session = RecordSession.get('main')

    def add_new_record(self, record: LangChainRecord, parent_chain: ConsoleRecord) -> None:
        record.save()
        if parent_chain and isinstance(parent_chain, LangChainLogger.CurrentChain):
            parent_chain = parent_chain.current_record

        if parent_chain and isinstance(parent_chain, LangChainRecord):
            parent_chain.add_child(record)
            parent_chain.save()
            record.save()
        
        self.current_session.add_record(record)
        self.current_session.save()

        #tree = self.current_session.get_as_full_tree()
        #self.warn(json.dumps(tree, indent=2))

    def format_input(self, input: Any) -> Any:
        if input is None:
            return None
        if type(input) == int:
            return input
        if type(input) == float:
            return input
        if type(input) == bool:
            return input
        if type(input) == str:
            return input
        
        if type(input) == list:
            return [self.format_input(i) for i in input]
        
        if type(input) == dict:
            return {k: self.format_input(v) for k, v in input.items()}

        if isinstance(input, AddableDict):
            return self.format_input(dict(**input))

        if isinstance(input, OpenAIToolAgentAction):
            return self.format_input(dict(
                name = 'ToolAgentAction',
                log = input.log,
                tool = input.tool,
                tool_call_id = input.tool_call_id,
                tool_input = input.tool_input,
            ))

        if isinstance(input, SaveLoadObject) and not isinstance(input, Agent):
            return self.format_input(input.to_json(force_json=True))
        
        if hasattr(input, 'get_simple_json'):
            return self.format_input(input.get_simple_json())

        if (
            isinstance(input, Serializable)
            or hasattr(input, 'to_json')
        ):
            return self.format_input(input.to_json())


        return f'[{type(input).__name__}]'

    def reset_to_tag(self, tag:str, **kwargs: Any):
        chain_remove, tool_remove = super().reset_to_tag(tag, **kwargs)
        for chain in chain_remove:
            if not chain.current_record:
                continue
            if isinstance(chain.current_record, UnknownRecord):
                self.clean_up_unknown(chain.current_record)
        return chain_remove, tool_remove

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        super().on_llm_start(serialized, prompts, **kwargs)

        kwargs = serialized.get('kwargs', {})
        record = LLMInvocationRecord(
            input=prompts,
            model=kwargs.get('model', None),
            args=kwargs.get('model_kwargs', {})
        )
        model = serialized.get('model')

        if not record:
            return

        record.ensure_id()
        if self.current_llm_call:
            assert(isinstance(self.current_llm_call, WebConsoleLogger.CurrentLLMCall))
            self.current_llm_call.current_record = record
        
        self.add_new_record(record, self.current_chain)

    def on_llm_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        gen = outputs.generations[0][0]
        message = gen.message # TODO get metadata with toolcalls not just content
        if isinstance(message, AIMessageChunk):
            message = dict(
                content=get_text_content(message.content, include_tools=True),
                additional_kwargs=message.additional_kwargs
            )
        elif isinstance(message, AIMessage):
            message = dict(
                content=get_text_content(message.content, include_tools=True),
                additional_kwargs=message.additional_kwargs
            )
        elif message.type == 'ai':
            message = dict(
                content=get_text_content(message.content, include_tools=True),
            )
        else:
            self.warn_static(f'Unknown message type: {message}')
            return

        if self.current_llm_call:
            assert(isinstance(self.current_llm_call, WebConsoleLogger.CurrentLLMCall))
            self.current_llm_call.current_record.output = self.format_input(message)
            self.current_llm_call.save()
        self.current_llm_call = None

        super().on_llm_end(outputs, **kwargs)
    
    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> Any:
        tool_before = self.current_tool
        super().on_tool_start(serialized, input_str, **kwargs)

        record = ToolCallRecord(
            input=self.format_input(input_str),
            tool=serialized,
        )

        record.ensure_id()
        if self.current_tool:
            assert(isinstance(self.current_tool, WebConsoleLogger.CurrentTool))
            self.current_tool.current_record = record

        self.add_new_record(record, self.current_chain)
    
    def on_tool_end(self, output: Any, **kwargs: Any) -> Any:
        if self.current_tool:
            assert(isinstance(self.current_tool, WebConsoleLogger.CurrentTool))
            record = self.current_tool.current_record
            record.output = self.format_input(output)
            self.current_tool.save()

        super().on_tool_end(output, **kwargs)

    def on_agent_annotation(self, name=None, text=None, severity=None, extra:Dict[str, Any]=None, **kwargs: Any) -> Any:
        record = AgentAnnotationRecord(
            annotation=name,
            input=text,
            severity=severity,
            extra=extra
        )
        record.ensure_id()
        self.add_new_record(record, self.current_chain)

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], *, run_id: UUID, parent_run_id: UUID | None = None, tags: List[str] | None = None, metadata: Dict[str, Any] | None = None, **kwargs: Any) -> Any:
        chain_before = self.current_chain

        super().on_chain_start(serialized, inputs)

        record = None

        cur_chain = self.current_chain
        if not cur_chain:
            self.warn(f'No added chain for on_chain_start with {serialized}')
            return

        cls_name = cur_chain.name
        cls = cur_chain.get_class()
        if cls:
            cls_name = cls.__name__

        if cls and issubclass(cls, Agent):
            # Log agent being invoked
            agent_id = cls.get_prop_from_serialized(serialized, 'id')
            record = AgentRecord(
                class_name=cls.get_class_name(),
                input=self.format_input(inputs),
                agent_id=agent_id,
            )
            if issubclass(cls, ChildAgent):
                record.parent_agent_id = cls.get_prop_from_serialized(serialized, 'parent_id')

        elif cls and issubclass(cls, RunnableSequence):
            # Log sequence being invoked
            record = SequenceRecord(
                class_name=cls.__name__,
                input=self.format_input(inputs)
            )

        elif cls and issubclass(cls, AgentExecutor):
            kwargs = serialized.get('kwargs', {})
            record = ToolExecutorRecord(
                class_name=cls.__name__,
                input=self.format_input(inputs),
                tools=kwargs.get('tools', [])
            )

        elif cls and issubclass(cls, ChatPromptTemplate):
            kwargs = serialized.get('kwargs', {})
            record = ChatPromptTemplateRecord(
                class_name=cls.__name__,
                input = self.format_input(inputs),
                input_variables = kwargs.get(
                    'input_variables', []
                ),
                messages = kwargs.get(
                    'messages', []
                ),
            )

        elif cls and issubclass(cls, output_parsers.BaseOutputParser):
            record = OutputParserRecord(
                class_name=cls.__name__,
                input=self.format_input(inputs)
            )

        elif cls and issubclass(cls, BaseParser):
            record = OutputParserRecord(
                class_name=cls.__name__,
                input=self.format_input(inputs)
            )
        elif cls and cls in [
            RunnableAssign, RunnableParallel,
            RunnableLambda
        ]:
            record = UnknownRecord(
                class_name=cls.__name__,
                input=None
            )

        else:
            self.warn(f'Unexpected chain type: {cls or cls_name}')
            record = UnknownRecord(
                class_name=cls_name,
                input=None
            )

        if not record:
            return

        record.ensure_id()
        cur_chain = self.current_chain
        if cur_chain:
            assert(isinstance(cur_chain, WebConsoleLogger.CurrentChain))
            cur_chain.current_record = record
        self.add_new_record(record, chain_before)

        pass

    def clean_up_unknown(self, record: UnknownRecord):
        def remove_from(record, parent):
            if record or parent is None:
                return
            index = parent.child_record_ids.index(record.id)
            parent.child_record_ids.pop(index)
            parent.save()

        if not isinstance(record, UnknownRecord):
            return

        if len(record.child_record_ids) == 0:
            # Remove the unknown dead end record
            remove_from(record, record.parent_record)
            return

        if not record.parent_record_id:
            # This is a top level unknown record
            return
        
        if len(record.child_record_ids) > 1:
            # If there are multiple children, we can't do anything atm
            return

        # Unlink the unknown record and replace it with the child
        parent = record.parent_record
        child = ConsoleRecord.get_by_id(record.child_record_ids[0])
        child.parent_record_id = parent.id

        index = parent.child_record_ids.index(record.id)
        parent.child_record_ids[index] = child.id

        parent.save()
        child.save()

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> Any:
        cur_chain = self.current_chain
        if not cur_chain:
            return super().on_chain_end(outputs, **kwargs)

        assert(isinstance(cur_chain, WebConsoleLogger.CurrentChain))
        record = cur_chain.current_record
        if record:
            if isinstance(record, UnknownRecord):
                self.clean_up_unknown(record)
            else:
                record.output = self.format_input(outputs)

        cur_chain.save()
        
        return super().on_chain_end(outputs, **kwargs)

import argparse

def web_console_main():
    argp = argparse.ArgumentParser(description='')
    argp.add_argument('--host', default='0.0.0.0', help='The host to bind to')
    argp.add_argument('--port', default=5000, help='The port to bind to')
    argp.add_argument('--data', default='./volumes', help='The directory to store data (normally named volumes)')

    args = argp.parse_args()
    args.data = os.path.abspath(args.data)
    
    # Get parent of data directory
    parent = os.path.dirname(args.data)
    os.chdir(parent)

    app.run(host=args.host, port=args.port)
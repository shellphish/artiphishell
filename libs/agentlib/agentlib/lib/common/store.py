import os
import json
from pathlib import Path
from typing import Union, Optional, Any, Dict, List, Generic

from langchain.storage import LocalFileStore
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.runnables.utils import Input, Output
from langchain_core.pydantic_v1 import Field, validator
from langchain.storage import LocalFileStore

from .base import BaseLogger
from .object import FileBackedObject, BaseObject, PersistentObject, LocalObject, RepoObject, CAN_SAVE_OBJECTS

PRETTY_JSON = True


class JsonIndexStore(BaseLogger, LocalFileStore):
    def __init__(self, index_path: str, data_path: str):
        if CAN_SAVE_OBJECTS:
            os.makedirs(index_path, exist_ok=True)
            os.makedirs(data_path, exist_ok=True)
        super().__init__(index_path)
        self.data_path = data_path
        self.pretty_json = PRETTY_JSON

    def load_object_from_json(self, data: str):
        return json.loads(data)

    def resolve_index_to_path(self, index: str) -> str:
        v = self.mget([index])
        #print(f'Got {v} for {index}')
        if not v or len(v) == 0 or not v[0]:
            return None
        fname = v[0].decode()
        fname = os.path.basename(fname)
        return os.path.join(self.data_path, fname)

    def get_blob(self, name) -> Optional[Dict[str, Any]]:
        data_path = self.resolve_index_to_path(name)
        with open(data_path, 'r') as f:
            return json.load(f)

    def dump_object_to_json(self, obj) -> str:
        if self.pretty_json:
            return json.dumps(obj, indent=2)
        return json.dumps(obj)

    def get_filepath_for_name(self, name):
        name = name.replace(' ', '_')
        name = ''.join(c for c in name if c.isalnum() or c in '_-')
        file_name = f'{name}.json'
        file_path = os.path.join(self.data_path, file_name)
        return name, file_path

    def set_indexes(self, val: str, *keys):
        if not CAN_SAVE_OBJECTS:
            return
        keys = [*keys]
        items = [(key, val.encode()) for key in keys]
        super().mset(items)
        
    
    def set_blob(self, name, data, *keys):
        if not CAN_SAVE_OBJECTS:
            return
        file_path = self.get_filepath_for_name(name)
        tmp_file_path = file_path + '.tmp'

        data = self.dump_object_to_json(data)
        with open(tmp_file_path, 'w') as f:
            f.write(data)
        os.rename(tmp_file_path, file_path)

        self.set_indexes(file_path, name, *keys)

        
#j = JsonIndexStore('./volumes/skills/index', './volumes/skills/skills')
#j.set_blob({'test': 'test'}, 'test')

class LocalObjectStore(JsonIndexStore):
    def __init__(
        self,
        index_path: str,
        data_path: str,
        data_class = FileBackedObject
    ):
        super().__init__(index_path, data_path)
        self.base_class_type = data_class

    def get(self, name: str) -> Optional[FileBackedObject]:
        data_path = self.resolve_index_to_path(name)
        #self.debug(f'Resolved index {name} to {data_path}')
        if not data_path:
            return None
        res = self.base_class_type.from_file(data_path)
        return res

    def get_filename_for_object(self, obj: FileBackedObject) -> str:
        return os.path.join(self.data_path, obj.get_new_filename())

    def upsert(self, obj: FileBackedObject, *keys) -> None:
        if not isinstance(obj, FileBackedObject):
            raise ValueError('Object must be a FileBackedObject')

        data_path = self.get_filename_for_object(obj)

        obj.save_to_path(path=data_path)
        super().set_indexes(obj.filepath, *obj.get_indexes(), *keys)
        #self.debug(f'Added {obj.id} to datastore@{data_path}')


    
class ObjectRepository(BaseObject):
    __ROOT_DIR__ = None
    __OBJECT_CLASS__ = None
    __EMBEDDING_FUNCTION__ = OpenAIEmbeddings
    __VECTOR_STORE_ENABLED__ = False

    def get_unique_id(self):
        return f'{self.get_class_name()}/{self.__ROOT_DIR__}/{self.name}'

    def get_object_store(self, *args, **kwargs):
        return LocalObjectStore(
            os.path.join(self.path, 'index'),
            os.path.join(self.path, 'data'),
            data_class=self.__OBJECT_CLASS__
        )
    
    def new_vector_store(self, collection_name: str, **kwargs):
        return Chroma(
            collection_name=collection_name,
            embedding_function=self.__EMBEDDING_FUNCTION__,
            persist_directory=os.path.join(self.path, 'vectors'),
            **kwargs
        )

    def __init__(self, name: str, path: str=None):
        super().__init__()
        self.name = name
        self.path = path
        if self.path is None:
            self.path = os.path.join(self.__ROOT_DIR__, name)
        self.store = self.get_object_store()

        if self.__VECTOR_STORE_ENABLED__:
            self.vectordb = self.new_vector_store(f'skills_{name}')
        else:
            self.vectordb = None


    def get_by_name(self, name: str):
        res = self.store.get(name)
        if isinstance(res, RepoObject):
            res.__from_repo__ = self
        return res
    
    def get_by_id(self, id: str):
        return self.get_by_name(id)

    def get_similar(self, query, limit=10):
        raise NotImplementedError()

    def insert(self, obj: PersistentObject):
        # TODO check if already exists
        return self.upsert(obj)

    def upsert(self, obj: PersistentObject):
        self.store.upsert(obj)
        if self.__VECTOR_STORE_ENABLED__:
            # TODO
            raise NotImplementedError()
        return True


class LocalObjectRepository(ObjectRepository):
    __ROOT_DIR__ = Path('volumes/general').resolve()
    __OBJECT_CLASS__ = LocalObject

LocalObject.__REPO__ = LocalObjectRepository('generic_data')
import os
import sys
import uuid
import json
from typing import List, Optional, Any, Dict, Type

import importlib

from langchain_core.load import load
from langchain.pydantic_v1 import Field
from langchain_core.pydantic_v1 import Extra
from langchain_core.runnables.utils import Input, Output
from langchain_core.load.serializable import Serializable

from .base import BaseObject, BaseRunnable

JSON_PRETTY_BY_DEFAULT = True

import warnings
from langchain_core._api.beta_decorator import LangChainBetaWarning

warnings.filterwarnings("ignore", category=LangChainBetaWarning)

CAN_SAVE_OBJECTS = os.getenv('AGENTLIB_SAVE_FILES', '1')
CAN_SAVE_OBJECTS = CAN_SAVE_OBJECTS.lower() not in (
    '0', 'false', 'no', 'off', 'disable',
    'disabled', 'nope', 'nah', 'n', ''
)

class SaveLoadObject(BaseObject, Serializable):
    @classmethod
    def _permissive_json_serializer(cls, obj):
        return str(obj)

    @classmethod
    def from_pydantic(cls, obj, **kw):
        kv = {
            k: getattr(obj, k)
            for k in obj.__fields__.keys()
        }
        kv.update(kw)
        return cls(**kv)

    @classmethod
    def _jsonify_all_fields(cls, v, parent=None, **kw):
        if type(v) is dict:
            v = v.copy()
            for k, vv in v.items():
                v[k] = cls._jsonify_all_fields(vv, parent=v, **kw)
        elif type(v) is list:
            v = v.copy()
            for i, vv in enumerate(v):
                v[i] = cls._jsonify_all_fields(vv, parent=v, **kw)
        elif (
            isinstance(v, SaveLoadObject)
        ):
            return v.to_json_as_property(parent=parent, **kw)
        elif (
            isinstance(v, Serializable)
        ):
            return v.to_json()
        return v

    def to_json_as_property(self, parent=None, **kw) -> dict:
        """
        Save the object to a json dictionary when it is a property of another class
        Overriding classes can use this to return a json reference type which can be used to look up the object by overriding the `TODO` method.
        """
        return self.to_json(**kw)

    def to_json(self, force_json=False, do_save=False) -> dict:
        res = super().to_json()
        res_j = self._jsonify_all_fields(
            res,
            force_json=force_json, 
            do_save=do_save,
        )
        mod_name = self.__class__.__module__
        mod_start = mod_name.split('.')[0]

        if mod_start in ['agentlib','langchain']:
            return res_j

        try:
            mod_path = sys.modules[mod_name].__file__
            mod_path = os.path.abspath(mod_path)
            res_j['mph'] = mod_path
        except:
            pass

        return res_j

    @staticmethod
    def get_valid_namespaces(base: "SaveLoadObject"=None) -> List[str]:
        if base is None:
            base = SaveLoadObject
        out = set()
        out.add(base.get_lc_namespace()[0])

        all_subclasses = list(base.__all_subclasses__())
        for subcls in all_subclasses:
            if not subcls.is_lc_serializable():
                continue

            out.add(subcls.get_lc_namespace()[0])

        return list(out) + [
            'agentlib.lib.common.base',
            'agentlib.lib.common.code',
            'agentlib.lib.common.logger',
            'agentlib.lib.common.object',
            'agentlib.lib.common.parsers',
            'agentlib.lib.common.store',
        ]
    
    @classmethod
    def _preprocess_module_object(cls, obj: dict, namespaces: list=None) -> dict:
        # We want to support loading objects from modules which are not yet imported. However some of these might not be in our python path or might be __main__
        # We can use a path hint if available to help us load the correct module

        obj_id = obj.get('id')
        if len(obj_id) < 2:
            return obj

        mod_name = '.'.join(obj_id[:-1])
        mod_parts = mod_name.split('.')
        mod_start = mod_parts[0]

        if mod_start in ['agentlib','langchain']:
            # These should always be already imported
            return obj
        
        mod_path_hint = obj.get('mph', None)
        if not mod_path_hint and mod_start == '__main__':
            # Look at args to see if we can find a hint
            for arg in sys.argv:
                if arg.endswith('.py'):
                    mod_path_hint = os.path.abspath(arg)
                    break
            # We will just guess that the module is main.py in the current directory
            if not mod_path_hint and os.path.exists('./main.py'):
                mod_path_hint = os.path.abspath('./main.py')

        if not mod_path_hint:
            return obj

        if not os.path.exists(mod_path_hint):
            # If its not a valid path, we can't add it to the path, so fall back to the default behavior
            return obj

        mod_path_file_name = os.path.basename(mod_path_hint)

        if mod_start == '__main__':
            # get current __main__ path
            if '__main__' not in sys.modules:
                mod_path = None
            else:
                mod_path = sys.modules['__main__'].__file__
                mod_path = os.path.abspath(mod_path)
            
            if mod_path == mod_path_hint:
                return obj
            
            # Other wise we need to override the module name from __main__ to the correct module
            mod_name = mod_path_file_name.replace('.py','')

            # Correct the id to the new module name
            obj['id'] = [mod_name, obj_id[-1]]
        
        # XXX YOLO who cares about deserialization vulns anyway
        if namespaces is not None:
            namespaces.append(mod_name)
        
        # Check to see if it is the correct module
        if mod_name in sys.modules:
            mod_path = sys.modules[mod_name].__file__
            mod_path = os.path.abspath(mod_path)
            if mod_path == mod_path_hint:
                return obj

            # A module with this name is already loaded but has a different path, so probably a different module?

            # TODO turn this into a warning instead of an error
            raise ValueError(f'Tried to load serialized object {obj_id}. However {mod_name} is already loaded but has a different path than expected: `{mod_path}` != `{mod_path_hint}`')

        try:
            importlib.import_module(mod_name)
        except Exception as e:
            # I hope this doesn't break anything :)
            sys.path.append(os.path.dirname(mod_path_hint))

        return obj

    @classmethod
    def _preprocess_json_before_load(cls, obj: Any, namespaces: List) -> dict:
        if not isinstance(obj, dict):
            return obj

        obj_id = obj.get('id')
        kwargs = obj.get('kwargs')

        if (
            obj.get('lc')
            and obj_id and kwargs
            and isinstance(kwargs, dict)
            and isinstance(obj_id, list)
        ):
            obj = cls._preprocess_module_object(obj, namespaces)

        # Recursively preprocess the json
        for k,v in obj.items():
            if isinstance(v, dict):
                obj[k] = cls._preprocess_json_before_load(v, namespaces)
            elif isinstance(v, list):
                obj[k] = [cls._preprocess_json_before_load(vv, namespaces) for vv in v]
        return obj

        
    @classmethod
    def from_json(cls, obj) -> "SaveLoadObject":
        if type(obj) == str:
            obj = json.loads(obj)

        namespaces = SaveLoadObject.get_valid_namespaces()
        namespaces += ['common.base']

        obj = cls._preprocess_json_before_load(obj, namespaces)

        res = load(obj, valid_namespaces=namespaces)

        if not isinstance(res, cls):
            raise ValueError(f'Invalid type: {type(res)}')
        return res

    @classmethod
    def is_lc_serializable(cls) -> bool:
        """Return whether this class is serializable."""
        return True
    @classmethod
    def get_lc_namespace(cls) -> list[str]:
        """Get the namespace of the langchain object."""
        return [cls.__module__]

    @property
    def lc_attributes(self) -> Dict:
        res = super().lc_attributes
        res.update({
            k: getattr(self, k)
            for k, v in self.__fields__.items()
        })
        return res

    class Config:
        extra = Extra.allow
        arbitrary_types_allowed = True

    def dump_to_json(
            self,
            force_json=False,
            pretty=JSON_PRETTY_BY_DEFAULT,
            do_save=False
    ) -> str:
        data = self.to_json(
            force_json=force_json,
            do_save=do_save
        )
        return json.dumps(
            data,
            default=self._permissive_json_serializer,
            indent=2 if pretty else None
        )

class SaveLoadWithId(SaveLoadObject):
    id: Optional[str] = None

    def ensure_id(self):
        if self.id is None:
            self.id = str(uuid.uuid4())
    
    def get_id(self):
        self.ensure_id()
        return self.id

    def get_simple_json(self):
        return f'<{self.get_class_name()} id={self.id}>'

    @classmethod
    def get_prop_from_serialized(cls, obj: dict, name='id') -> str:
        return obj.get('kwargs', {}).get('id', None)

    def to_json(self, **kw) -> dict:
        self.ensure_id()
        return super().to_json(**kw)

    def get_indexes(self):
        return [self.id]

class PersistentObject(SaveLoadWithId):
    """
    An object which can be saved and loaded from a file.
    The object has an ID which can be used to uniquely identify it and load it.
    """
    def save(self, *args, **kwargs):
        raise NotImplementedError
    @classmethod
    def load_by_id(cls, id):
        raise NotImplementedError
    @classmethod
    def get_by_id(cls, id):
        return cls.load_by_id(id)
    @classmethod
    def filter(cls, **kwargs):
        """ Perform a filter search with the given kwargs. """
        raise NotImplementedError

    @classmethod
    def get_blocked_fields_for_pydantic(cls):
        return ['id', 'filepath']
    
    @classmethod
    def schema(cls, *args, **kw) -> dict:
        out = super(PersistentObject, cls).schema()
        out = dict(**out)
        props = out.get('properties', {})
        for k in cls.get_blocked_fields_for_pydantic():
            props.pop(k, None)
        return out
    

class PersistentWithVectors(PersistentObject):
    pass

class FileBackedObject(PersistentObject):
    """
    An object which is backed by a specific file on disk.
    FileBackedObjects can't be searched on their own as they are not indexed.
    """
    filepath: Optional[str] = None

    @classmethod
    def load_existing_or_create(
        cls, save_path: str, *args,
        force_json=True, **kwargs
    ):
        if os.path.exists(save_path):
            return cls.from_file(save_path)
        cls.warn_static(f'File does not exist: {save_path}, creating new object')
        inst = cls(*args, **kwargs)
        inst.save(path=save_path, force_json=force_json)
        return inst
        

    def get_new_filename(self):
        self.ensure_id()
        return f'{self.get_class_name()}_{self.id}.json'

    def get_indexes(self):
        return [self.id]

    def save_to_path(
            self,
            path:str,
            force_json=False,
            pretty=JSON_PRETTY_BY_DEFAULT,
            **kw
    ):
        self.ensure_id()

        if not CAN_SAVE_OBJECTS:
            return True

        if not path:
            raise ValueError('No path provided')

        tpath = path + '.tmp'
        with open(tpath, 'w') as f:
            f.write(self.dump_to_json(
                force_json=force_json,
                pretty=pretty,
                do_save=True
            ))
        os.rename(tpath, path)

        #self.debug(f'Saved {self.get_class_name()} to {path}')
        self.filepath = path

        return True

    def delete_file(self):
        if not CAN_SAVE_OBJECTS:
            return
        if self.filepath:
            os.remove(self.filepath)
            self.warn(f'Deleted {self.get_class_name()} file: {self.filepath}')

    def save(self, path:str=None, **kw):
        if path is None:
            path = self.filepath
        return self.save_to_path(path, **kw)

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'r') as f:
            return cls.from_json(f.read())

    @classmethod
    def reload_id_from_file_or_new(cls, filepath, *args, force_json=True, **kwargs):
        return cls.load_existing_or_create(filepath, *args, force_json=force_json, **kwargs)

class NamedFileObject(FileBackedObject):
    name: Optional[str] = None

    def sanitize_name(self):
        if self.name is None:
            raise ValueError('No name provided')
        name = self.name
        name = name.replace(' ', '_')
        name = ''.join(c for c in name if c.isalnum() or c in '_-')
        self.name = name
        return name

    def get_new_filename(self):
        self.ensure_id()
        self.sanitize_name()
        return f'{self.name[:32]}_{self.id}.json'

    def get_indexes(self):
        self.sanitize_name()
        return [self.name, self.id]

class RepoLoader(SaveLoadObject):
    """
    A class which can load objects from a repository when constructed.
    """
    class_name: str
    object_id: str

    @classmethod
    def get_intended_class(cls, class_name: str):
        target = RepoObject.__all_subclasses_map__().get(class_name)
        if not target:
            raise ValueError(f'Invalid class name: {class_name}')
        return target

    def __new__(cls, *args, **kwargs):
        if kwargs.pop('__no_load', False):
            return super().__new__(cls)
        proxy_cls = cls.get_intended_class(kwargs['class_name'])
        return proxy_cls.load_by_id(kwargs['object_id'])

    def __init__(self, *args, **kwargs):
        kwargs.pop('__no_load', False)
        super().__init__(*args, **kwargs)


class RepoObject(PersistentObject):
    __REPO__ = None
    """ Controls what local repo the objects are saved/loaded from. Base Type: common.store.LocalObjectRepository"""

    __WEAK_PROPERTIES__ = None

    @classmethod
    def fix_weak_keys(cls, obj):
        if not cls.__WEAK_PROPERTIES__:
            return obj

        for prop_name, prop_info in cls.__WEAK_PROPERTIES__.items():
            prop_id_name = prop_info['prop_id_name']
            if not prop_name in obj:
                continue
            val = obj[prop_name]
            if val and not isinstance(val, RepoObject):
                cls.warn(f'Invalid weak property: {prop_name}, {repr(val)} is not a RepoObject')
                continue
            val = val.id
            del obj[prop_name]
            obj[prop_id_name] = val

        return obj

    @classmethod
    def __all_sub_repos__(cls, superclass=None):
        from . import store

        all_repos = {}
        my_repo: store.ObjectRepository = cls.__REPO__
        if my_repo:
            all_repos[my_repo.get_unique_id()] = cls

        def update_if_more_based(map, key, challenger):
            if key in map:
                existing = map[key]
                if issubclass(challenger, existing):
                    # The challenger is a subclass of the existing class, making it less based
                    return False
                if not issubclass(existing, challenger):
                    cls.warn_static(f'Invalid class hierarchy: {challenger} and {existing} do not share an inheritance relationship')
                    raise ValueError(f'Invalid class hierarchy: {challenger} and {existing} do not share an inheritance relationship')

            # The challenger is a superclass of the existing class, making it more based
            map[key] = challenger
            return True

        for subc in cls.__subclasses__():
            subc_repos = subc.__all_sub_repos__(superclass=cls)
            for k, v in subc_repos.items():
                update_if_more_based(all_repos, k, v)

        return all_repos

    @classmethod
    def _install_weak_properties(cls):
        weak_properties = {}
        from . import store

        if cls.__REPO__:
            if not isinstance(cls.__REPO__, store.ObjectRepository):
                raise ValueError(f'Invalid {cls.__name__}.__REPO__ type: {cls.__REPO__}. Did you forget to construct the class?')

        # Define property loaders and setters for weak properties
        for prop_id_name,v in cls.__fields__.items():
            extra = v.field_info.extra
            is_weak = extra.get('is_weak', False)
            if not is_weak:
                continue

            # Weak property must be an loaded class
            weak_class = extra.get('weak_class', None)
            if not weak_class:
                weak_class = RepoObject

            prop_name = extra.get('prop_name')
            if not prop_name:
                if prop_id_name.endswith('_id'):
                    prop_name = prop_id_name[:-3]
            if not prop_name:
                raise ValueError(f'Invalid weak property: {prop_id_name}, no prop_name provided')

            if prop_name in cls.__dict__:
                # Property already defined
                continue

            # Get the class that is defined for the weak property
            repo_obj_class = RepoObject.__all_subclasses_map__().get(weak_class)
            if not repo_obj_class:
                raise ValueError(f'Invalid weak class: {weak_class}')

            def create_property(prop_name_in, prop_id_name_in, repo_obj_class_in):

                # The getter property will load the object from the repo
                class Getter(object):
                    prop_name = prop_name_in
                    prop_id_name = prop_id_name_in

                    @staticmethod
                    def __call__(self):
                        id_val = getattr(self, Getter.prop_id_name)
                        if not id_val:
                            return None
                        cache_prop_name = '_' + Getter.prop_name
                        cache_prop_val = getattr(self, cache_prop_name, None)
                        if cache_prop_val:
                            return cache_prop_val

                        print(f"Getting {Getter.prop_name} with id {id_val}")
                        return repo_obj_class.load_by_id_from_sub(id_val)

                class Setter(object):
                    prop_name = prop_name_in
                    prop_id_name = prop_id_name_in

                    @staticmethod
                    def __call__(self, value):
                        if isinstance(value, RepoObject):
                            value = value.id

                        setattr(self, Setter.prop_id_name, value)

                prop = property(Getter(), Setter())
                return prop

            prop = create_property(prop_name, prop_id_name, repo_obj_class)

            weak_properties[prop_name] = dict(
                prop=prop,
                prop_id_name=prop_id_name
            )

        if len(weak_properties) == 0:
            return

        for prop_name, prop_info in weak_properties.items():
            prop = prop_info['prop']
            setattr(cls, prop_name, prop)
        
        if not cls.__WEAK_PROPERTIES__:
            cls.__WEAK_PROPERTIES__ = weak_properties
        else:
            other_props = dict(**cls.__WEAK_PROPERTIES__)
            other_props.update(**weak_properties)
            cls.__WEAK_PROPERTIES__ = other_props
    
    def __setattr__(self, name, value):
        if self.__WEAK_PROPERTIES__ and name in self.__WEAK_PROPERTIES__:
            prop_info = self.__WEAK_PROPERTIES__[name]
            prop = prop_info['prop']
            return prop.fset(self, value)
        return PersistentObject.__setattr__(self, name, value)

    def __new__(cls, *args, **kwargs):
        cls._install_weak_properties()
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        __from_repo__ = kwargs.pop('from_repo', self.__REPO__)
        kwargs = self.fix_weak_keys(dict(**kwargs))

        # Must init pydantic first before adding properties
        PersistentObject.__init__(self, **kwargs)

        self.__from_repo__ = __from_repo__
        pass

    def save(self, *args, **kwargs):
        if not CAN_SAVE_OBJECTS:
            return True
        if self.__from_repo__ is None:
            raise ValueError(f'Cannot save {self.get_class_name()} without a provided __REPO__')
        return self.__from_repo__.upsert(self)

    def to_json_as_property(self, parent=None, force_json=False, do_save=False, **kw):
        force_json = force_json or not CAN_SAVE_OBJECTS
        if not hasattr(self, '__from_repo__') or self.__from_repo__ is None:
            if self.__class__.__REPO__:
                self.warn(f'Invalid __from_repo__ value: {self.__from_repo__} on {self.get_class_name()}')

        if not hasattr(self, '__from_repo__') or self.__from_repo__ is None or force_json:
            return super().to_json_as_property(parent=parent, force_json=force_json, **kw)

        if not hasattr(self, 'id') or not self.id:
            self.save()
        elif do_save:
            self.save()

        return RepoLoader(
            class_name=self.get_class_name(),
            object_id=self.id,
            __no_load=True
        ).to_json_as_property(parent=parent)
    
    @classmethod
    def load_by_id(cls, id) -> "RepoObject":
        if cls.__REPO__ is None:
            raise ValueError(f'Cannot load {cls.__name__} without a provided __REPO__')
        return cls.__REPO__.get_by_id(id)

    @classmethod
    def load_by_id_from_sub(cls, id):
        res = cls.load_by_id(id)
        if res:
            return res

        all_repos = cls.__all_sub_repos__()
        for repo_id, repo_cls in all_repos.items():
            res = repo_cls.get_by_id(id)
            if res:
                return res
        return None
    
    @classmethod
    def Weak(cls, prop_name=None):
        """
        Defines a weak property relationship on the class
        When this property is accessed, the id will be looked up
        """
        return Field(None,
            is_weak=True,
            weak_class=cls.__name__,
            prop_name=prop_name
        )
        
class LocalObject(RepoObject,FileBackedObject):
    def __init__(self, **kw):
        RepoObject.__init__(self, **self.fix_weak_keys(dict(**kw)))
        self._loaded_from_path = None

    @classmethod
    def load_existing_or_create(
        cls, save_path: str, *args,
        force_json=True, **kwargs
    ):
        if os.path.exists(save_path) and CAN_SAVE_OBJECTS:
            tmp = cls.from_file(save_path)
            if not hasattr(tmp, 'id') or not tmp.id:
                return tmp
            tmp: LocalObject = cls.load_by_id(tmp.id) or tmp
            tmp._loaded_from_path = save_path
            cls.info_static(f'Reloading {tmp.get_class_name()} instance from {save_path}, with id {tmp.id}')
            return tmp

        inst = cls(*args, **kwargs)
        inst.ensure_id()
        if CAN_SAVE_OBJECTS:
            cls.warn_static(f'File does not exist: {save_path}, creating new {inst.get_class_name()} instance with id {inst.id}')
            inst._loaded_from_path = save_path
            inst.save()
        return inst

    def save_copy(self):
        cop = self.copy()
        cop.save()
        return cop

    def save(self, path:str=None, *args, force_json=False, **kwargs):
        if not CAN_SAVE_OBJECTS:
            return True
        if path is None and hasattr(self, '_loaded_from_path'):
            if (
                CAN_SAVE_OBJECTS
                and self._loaded_from_path
                and self._loaded_from_path != self.filepath
            ):
                self.debug(f'Saving {self.get_class_name()} to {self._loaded_from_path}')
                FileBackedObject.save(
                    self, self._loaded_from_path,
                    *args,
                    force_json=force_json,
                    **kwargs
                )
        if (
            CAN_SAVE_OBJECTS and (
                path is not None
                or self.__from_repo__ is None
                or force_json
            )
        ):
            return FileBackedObject.save(
                self, path,
                *args,
                force_json=force_json,
                **kwargs
            )
        return RepoObject.save(self, *args, **kwargs)


class RunnableLocalObject(LocalObject, BaseRunnable[Input, Output]):
    def __init__(self, *args, config=None, **kwargs):
        LocalObject.__init__(self, *args, **kwargs)
        BaseRunnable.__init__(self)
        if config:
            self.runnable_config = config

class SerializableType(SaveLoadObject):
    module: str
    type_name: str
    module_path_hint: Optional[str]
    
    def __init__(self, type: Type=None, **kwargs):
        if type:
            kwargs['module'] = type.__module__
            kwargs['type_name'] = type.__name__
            kwargs['file_path_hint'] = os.path.abspath(
                sys.modules[type.__module__].__file__
            )
        super().__init__(**kwargs)

    def get_type(self) -> Type:
        # Use the SaveLoadObject to handle finding the type for us
        obj = dict(
            lc=1,
            id=[self.module, self.type_name],
            kwargs={},
            mph=self.module_path_hint
        )
        obj = SaveLoadObject._preprocess_module_object(obj, None)
        mod_name = '.'.join(obj['id'][:-1])

        mod = importlib.import_module(mod_name)
        return getattr(mod, self.type_name)
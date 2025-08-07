from typing import Any, Callable, DefaultDict, List, Type, TypeVar
from collections import defaultdict
from neomodel import StructuredNode

NodeType = TypeVar('NodeType', bound=StructuredNode)

ALL_NODE_UPDATE_HOOKS : DefaultDict[NodeType, List[Callable[[Any], None]]] = defaultdict(list)

def register_for_node_update(clz: Type[NodeType]):
    def _decorator(func: Callable[[NodeType], None]):
        ALL_NODE_UPDATE_HOOKS[clz].append(func)
        return func
    return _decorator

def node_updated(node: NodeType):
    # import ipdb; ipdb.set_trace()
    # if node.__class__.__name__ == 'Reference':
    #     import ipdb; ipdb.set_trace()

    clz = type(node)
    for hook in ALL_NODE_UPDATE_HOOKS[clz]:
        hook(node)
    return node
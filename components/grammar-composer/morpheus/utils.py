import functools
import hashlib
import inspect
import logging
import math

from collections import Counter

from shellphish_crs_utils.utils import artiphishell_should_fail_on_error

LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("morpheus")


class OrderedSet():
    def __init__(self, iterable=None):
        self._set = set()
        self._order = []
        if iterable is not None:
            for item in iterable:
                self.add(item)
    
    def add(self, item):
        if item not in self._set:
            self._set.add(item)
            self._order.append(item)
            
    def update(self, iterable):
        for item in iterable:
            self.add(item)

    def __iter__(self):
        for item in self._order:
            yield item

    def __contains__(self, item):
        return item in self._set
    
    def __len__(self):
        return len(self._set)
    
    def __repr__(self):
        return f"OrderedSet({self._order})"

def replace_all(buffer: str, replacements: str):
    # first sort the replacements by length of the key (reversed)
    # this way we can replace the longest strings first
    replacements = sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True)
    # then replace all the strings with the hash of the key
    for key, _ in replacements:
        buffer = buffer.replace(key, hashlib.sha256(key.encode()).hexdigest())

    # then replace all the hashes with the corresponding value
    for key, value in replacements:
        buffer = buffer.replace(hashlib.sha256(key.encode()).hexdigest(), value)

    return buffer
    
def token_quality(token, cr_weight=0.5, alphabet_size=256):
    if not token:
        return 0.0
    L = len(token)
    # Calculate Shannon entropy from symbol frequencies.
    entropy = -sum((count / L) * math.log(count / L, 2) for count in Counter(token).values())
    # Collision resistance: 1 minus the collision probability.
    cr = 1 - 1 / (2 ** (L * entropy))
    # Normalized Byte Value: average byte value normalized by (alphabet_size - 1)
    nbv = sum(token) / (L * (alphabet_size - 1))
    return cr_weight * cr + (1 - cr_weight) * nbv

def exception_wrapper(exception_types=(Exception,), returnval=None):
    def actual_exception_wrapper(func):
        # NOTE: functools.wraps copies name, docstring, etc. to the wrapper function
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if inspect.isgeneratorfunction(func):
                def wrapped_generator():
                    try: 
                        yield from func(*args, **kwargs)
                    except exception_types as e:
                        if artiphishell_should_fail_on_error(): 
                            raise
                        log.error(f"Generator error in {func.__name__}: {e}")
                return wrapped_generator()
            else:
                try:
                    return func(*args, **kwargs)
                except exception_types as e:
                    if artiphishell_should_fail_on_error(): 
                        raise
                    log.error(f"Error in function {func.__name__}: {e}")
                    return returnval
        return wrapper
    return actual_exception_wrapper
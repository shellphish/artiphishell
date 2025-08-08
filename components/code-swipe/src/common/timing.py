import time
import functools
import logging
import inspect

logger = logging.getLogger(__name__)

def time_it(func):
    """Decorator to time a function's execution, logging class name for methods."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        elapsed_time = end_time - start_time

        # Determine the name to log
        func_name = func.__name__
        log_name = func_name
        
        try:
            # Check if the first argument exists and might be self or cls
            if args:
                first_arg = args[0]
                if hasattr(first_arg, '__class__'):
                    if isinstance(first_arg, type):
                        # Class method (@classmethod), first_arg is the class
                        class_name = first_arg.__name__
                        log_name = f"{class_name}.{func_name}"
                    else:
                        # Instance method, first_arg is the instance (self)
                        class_name = first_arg.__class__.__name__
                        log_name = f"{class_name}.{func_name}"
        except Exception:
            # Fallback in case of unexpected issues determining class name
            logger.warning(f"Could not determine class for {func_name}", exc_info=True)
            pass # Use default log_name

        logger.info(f"Execution time for {log_name}: {elapsed_time:.4f} seconds")
        return result
    return wrapper

__all__ = ["time_it"]

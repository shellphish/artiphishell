from contextlib import contextmanager
import os

from .config import Config

@contextmanager
def maybe_suppress_output():
    if not Config.suppress_run_pov_output:
        yield
        return
        
    # Save original file descriptors
    original_stdout_fd = os.dup(1)
    original_stderr_fd = os.dup(2)
    
    # Open devnull
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    
    try:
        # Redirect stdout and stderr to devnull
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)
        yield
    finally:
        # Restore original file descriptors
        os.dup2(original_stdout_fd, 1)
        os.dup2(original_stderr_fd, 2)
        
        # Close file descriptors
        os.close(original_stdout_fd)
        os.close(original_stderr_fd)
        os.close(devnull_fd)
        
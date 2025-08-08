

import json
import os

FUNCTIONS_MAPPING = None

def tool_error(message: str):
    """
    Print an error message and return it as a string.

    Args:
        message (str): The error message to print.
    
    Returns:
        str: The error message.
    """
    return f"[ERROR]: {message}"

def tool_success(message: str):
    """
    Print a success message and return the result

    Args:
        message (str): The result
    
    Returns:
        str: The success message.
    """
    return f"[SUCCESS]: {message}"

def tool_choice(message: str):
    """
    Print a choice message and return the result

    Args:
        message (str): The result
    
    Returns:
        str: The choice message.
    """
    return f"[CHOICES]: {message}"
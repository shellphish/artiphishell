class MaxToolCallsExceeded(Exception):
    def __init__(self):
        """
        Exception raised when an agent exceeds max tool calls.
        """
        super().__init__()
        
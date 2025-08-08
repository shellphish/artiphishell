

from pathlib import Path

class PatchIsDuplicate(Exception):
    def __init__(self, action, patch_hash):
        super().__init__()
        # NOTE: this is the action we want to replay (e.g., setting same feeback etc...)
        self.action = action
        self.patch_hash = patch_hash

class PatchFailedSanitization(Exception):
    def __init__(self, reason: str):
        """
        Exception raised when a patch fails sanitization.
        :param reason: The reason for the failure.
        """
        super().__init__()
        self.reason = reason

    def __str__(self):
        """
        String representation of the exception.
        :return: A formatted error message.
        """
        err = ''
        err += f'🙅🏻‍♂️ The patch failed sanitization!\n'
        err += f'Reason: {self.reason}\n'
        return err

class IncorrectFilePathException(Exception):
    def __init__(self, file_path: Path, reason: str):
        super().__init__()
        self.file_path = file_path
        self.reason = reason
        
    
    def __str__(self):
        err = ''
        err += f' 🙅🏻‍♂️ {self.file_path} does not exist!!\n'
        return err

class IllegalPatchLocationException(Exception):
    def __init__(self, reason: str):
        super().__init__()
        self.reason = reason
    
    def __str__(self):
        err = ''
        err += f'🙅🏻‍♂️ Illegal patch locations encountered!\n'
        err += f'Reasons: {self.reason}\n'
        return err

class WrongPatchLocationException(Exception):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason
    
    def __str__(self):
        err = ''
        err += f'Was not able to inser the patch code'

class OriginalCodeNotFoundException(Exception):
    def __init__(self, file_path: Path, original_code: str):
        super().__init__()
        self.file_path = file_path
        self.original_code = original_code
    
    def __str__(self):
        err = ''
        err += f'The original code was not found in {self.file_path}\n'
        err += f'Original code: <original>\n{self.original_code}\n</original>\n'
        return err
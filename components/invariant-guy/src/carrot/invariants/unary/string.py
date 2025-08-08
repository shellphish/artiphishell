

from ..base import BaseUnaryInvariant

class StringUnaryNotEmpty(BaseUnaryInvariant):
    '''
    Check if a string is always not null
    '''
    def __init__(self, var):
        self.name = "StringUnaryNotNull"
        self.var = var

    @staticmethod
    def check(vars) -> set:
        '''
        Attributes:
          - var is one var object belonging to a program point
        '''
        invs = set()
        for var_name, var_values in vars.items():
            if "" not in var_values:
                invs.add(StringUnaryNotEmpty(var_name))
        return invs
    
    def __str__(self):
        return f"{self.var}!=''"


class StringUnaryConstant(BaseUnaryInvariant):
    '''
    Check if a Var always holds a constant value.
    '''
    def __init__(self, var, val):
        self.name = "StringUnaryConstant"
        self.var = var
        self.val = val
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():

            # The var has a constant value if the size of the set is 1
            if len(var_values) == 1:
                constant_val = list(var_values)[0]
                invs.add(StringUnaryConstant(var_name, constant_val))
        return invs
    
    def __str__(self):
        return f"{self.var}=={self.val}"
    

class StringUnaryMaxLength(BaseUnaryInvariant):
    '''
    Check what is the historical max of the variable.
    '''
    def __init__(self, var, max_value):
        self.name = "StringUnaryMaxLength"
        self.var = var
        self.max_value = max_value
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            val_with_max_len = max(var_values, key=len)
            max_value = len(val_with_max_len)
            invs.add(StringUnaryMaxLength(var_name, max_value))
        
        return invs

    def __str__(self):
        return f"max(len({self.var}))=={self.max_value}"


class StringUnaryValueInList(BaseUnaryInvariant):
    '''
    Check if a Var always holds a constant value.
    '''
    def __init__(self, var, val):
        self.name = "StringUnaryValueInList"
        self.var = var
        self.val = val
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            invs.add(StringUnaryValueInList(var_name, str(var_values)))
        return invs
    
    def __str__(self):
        return f"{self.var} in {self.val}"
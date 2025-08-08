from ..base import BaseUnaryInvariant

class NumericalUnaryNotZeroInvariant(BaseUnaryInvariant):
    '''
    Check if a Var always holds numerical value 
    always different from zero.
    '''
    def __init__(self, var):
        self.name = "NumericalUnaryNotZeroInvariant"
        self.var = var
    
    @staticmethod
    def check(vars) -> set:
        '''
        Attributes:
          - var is one var object belonging to a program point
        '''
        invs = set()
        for var_name, var_values in vars.items():
            if all(val != 0 for val in var_values):
                invs.add(NumericalUnaryNotZeroInvariant(var_name))
        return invs

    def __str__(self):
        return f"{self.var}!=0"


class NumericalUnaryConstantInvariant(BaseUnaryInvariant):
    '''
    Check if a Var always holds a constant value.
    '''
    def __init__(self, var, val):
        self.name = "NumericalUnaryConstantInvariant"
        self.var = var
        self.val = val
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            # The var has a constant value if the size of the set is 1
            if len(var_values) == 1:
                the_value = list(var_values)[0]
                invs.add(NumericalUnaryConstantInvariant(var_name, the_value))
        return invs
    
    def __str__(self):
        return f"{self.var}=={self.val}"


class NumericalUnaryMax(BaseUnaryInvariant):
    '''
    Check what is the historical max of the variable.
    '''
    def __init__(self, var, max_value):
        self.name = "NumericalUnaryMaxInvariant"
        self.var = var
        self.max_value = max_value
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            invs.add(NumericalUnaryMax(var_name, var_values.max()))
        
        return invs
    
    def __str__(self):
        return f"max({self.var})=={self.max_value}"
    

class NumericalUnaryMin(BaseUnaryInvariant):
    '''
    Check what is the historical min of the variable.
    '''
    def __init__(self, var, min_value):
        self.name = "NumericalUnaryMinInvariant"
        self.var = var
        self.min_value = min_value
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            invs.add(NumericalUnaryMin(var_name, var_values.min()))
        
        return invs
    
    def __str__(self):
        return f"min({self.var})=={self.min_value}"
from ..base import BaseUnaryInvariant

class BooleanUnaryConstantInvariant(BaseUnaryInvariant):
    '''
    Check if a boolean is always true or false.
    '''
    def __init__(self, var, val):
        self.name = "BooleanUnaryConstantInvariant"
        self.var = var
        self.val = val
    
    @staticmethod
    def check(vars) -> set:
        invs = set()
        for var_name, var_values in vars.items():
            if len(var_values) == 1:
                # The vars has a constant value if the size of the set is 1
                the_value = list(var_values)[0]
                invs.add(BooleanUnaryConstantInvariant(var_name, the_value))
        return invs

    def __str__(self):
        return f"{self.var}=={self.val}"

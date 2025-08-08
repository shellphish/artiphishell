
import itertools

from .. import BaseBinaryInvariant

class NumericalBinaryXGreaterThanY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "NumericalBinaryXGreaterThanY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        '''
        Attributes:
           - vars: a dictionary of vars belonging to a program point
                       the keys are the name of the vars.
        Requires:
           - vars has at least two vars
           - all the vars passed as arguments must be numerical

        Returns:
           - A string representing the holding invariant, if the set is empty,
             none of the invariant holds.
        '''
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for var1, var2 in pairs:
            var1_observations, var2_observations = vars[var1], vars[var2]
            # check if ALL the values of arg_1_observations are less than the values of arg_2_observations
            if var1_observations.min() > var2_observations.max():
                invs.add(NumericalBinaryXGreaterThanY(var1, var2))

        return invs
    
    def __str__(self):
        return f"{self.var1}>{self.var2}"


class NumericalBinaryXLessThanY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "NumericalBinaryXLessThanY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        '''
        Attributes:
           - vars: a dictionary of vars belonging to a program point
                   the keys are the name of the vars.
        Requires:
           - vars has at least two vars
           - all the vars passed as arguments must be numerical

        Returns:
           - A string representing the holding invariant, if the set is empty,
             none of the invariant holds.
        '''
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for var1, var2 in pairs:
            var1_observations, var2_observations = vars[var1], vars[var2]
            # check if ALL the values of arg_1_observations are less than the values of arg_2_observations
            if var1_observations.max() < var2_observations.min():
                invs.add(NumericalBinaryXLessThanY(var1, var2))

        return invs

    def __str__(self):
        return f"{self.var1}<{self.var2}"
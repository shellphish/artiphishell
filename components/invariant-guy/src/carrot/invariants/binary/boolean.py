import itertools

from .. import BaseBinaryInvariant

class BooleanBinaryXY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "BooleanBinaryXY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for pair in pairs:
            var1, var2 = pair[0], pair[1]
            var1_values, var2_values = vars[var1], vars[var2]
            # check if ALL the values of arg_1_values are less than the values of arg_2_values
            if all(val1 is True and val2 is True for val1 in var1_values for val2 in var2_values):
                invs.add(BooleanBinaryXY(var1, var2))

        return invs

    def __str__(self):
        return f"{self.var1}==True and {self.var2}==True"


class BooleanBinaryXnotY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "BooleanBinaryXnotY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for pair in pairs:
            var1, var2 = pair[0], pair[1]
            var1_values, var2_values = vars[var1], vars[var2]
            # check if ALL the values of arg_1_values are less than the values of arg_2_values
            if all(val1 is True and val2 is False for val1 in var1_values for val2 in var2_values):
                invs.add(BooleanBinaryXnotY(var1, var2))

        return invs

    def __str__(self):
        return f"{self.var1}==True and {self.var2}==False"


class BooleanBinarynotXY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "BooleanBinarynotXY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for pair in pairs:
            var1, var2 = pair[0], pair[1]
            var1_values, var2_values = vars[var1], vars[var2]
            # check if ALL the values of arg_1_values are less than the values of arg_2_values
            if all(val1 is False and val2 is True for val1 in var1_values for val2 in var2_values):
                invs.add(BooleanBinarynotXY(var1, var2))

        return invs

    def __str__(self):
        return f"{self.var1}==False and {self.var2}==True"


class BooleanBinarynotXnotY(BaseBinaryInvariant):
    def __init__(self, var1, var2):
        self.name = "BooleanBinarynotXnotY"
        self.var1 = var1
        self.var2 = var2

    @staticmethod
    def check(vars:dict):
        if len(vars) < 2:
            return set()

        invs = set()

        # get all the pairs of vars
        pairs = list(itertools.combinations(vars.keys(), 2))

        # for every pairs, check if the values of var1 is always lt the values of var2
        for pair in pairs:
            var1, var2 = pair[0], pair[1]
            var1_values, var2_values = vars[var1], vars[var2]
            # check if ALL the values of arg_1_values are less than the values of arg_2_values
            if all(val1 is False and val2 is False for val1 in var1_values for val2 in var2_values):
                invs.add(BooleanBinarynotXnotY(var1, var2))

        return invs

    def __str__(self):
        return f"{self.var1}==False and {self.var2}==False"
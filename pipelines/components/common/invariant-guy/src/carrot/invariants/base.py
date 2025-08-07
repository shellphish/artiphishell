


class BaseInvariant():
    '''
    Just an abstract class for invariants.
    '''
    def __init__(self):
        pass
    
    def check(self, var) -> set:
        raise NotImplementedError("This is an abstract class")

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return str(self) == str(other)

class BaseUnaryInvariant(BaseInvariant):
    '''
    Just an abstract class for unary invariants.
    '''
    def __init__(self):
        pass

    def is_comparable(self, other):
        return self.name == other.name and self.var == other.var


class BaseBinaryInvariant(BaseInvariant):
    '''
    Just an abstract class for binary invariants.
    '''
    def __init__(self):
        pass
    
    def is_comparable(self, other):
        return self.name == other.name and self.var1 == other.var1 and self.var2 == other.var2
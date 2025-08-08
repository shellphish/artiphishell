
import bisect
from collections import defaultdict

from .invariants import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    # Background colors:
    GREYBG = '\033[100m'
    REDBG = '\033[101m'
    GREENBG = '\033[102m'
    YELLOWBG = '\033[103m'
    BLUEBG = '\033[104m'
    PINKBG = '\033[105m'
    CYANBG = '\033[106m'

MIN_OBSERVATIONS = 2

class Observations(set):
    def __init__(self, observations=None):
        set.__init__(self, [])

        self.type = None
        self._sorted = []
        observations = observations or []
        for observation in observations:
            self.add(observation)

    def add(self, observation):
        if self.type is None:
            self.type = type(observation)
        
        if observation not in self:
            bisect.insort(self._sorted, observation)
            set.add(self, observation)

    def min(self):
        return self._sorted[0]
    
    def max(self):
        return self._sorted[-1]
        

class ProgramPoint:
    '''
    A program point is a specific point in the program.
    e.g., the entering of a function, the exit, or,
          somewehere in the middle.
    A program point is associated with multiple vars.
    These vars are the variable we want to annotate at that
    specific location.

    Attributes:
        - name: the unique name of the program point
        - vars: the arguments of the program point
                this is a dictionary like: { var_name: [values] }
        - observations: the number of observations of the program point
        - invariants: the invariants holding for the program point
    '''
    def __init__(self, name:str):
        self.name = name
        self.vars = defaultdict(Observations)
        self.observations = 0
        self.invariants = set()
        self.in_crashing_trace = False

    def add_observation(self, vars):
        '''
        Add an observation to the program point.
        '''
        self.observations += 1
        for var in vars:
            try:
                var_name = var.split("=")[0]
                var_value = var.split("=")[1]
                var_value = int(var_value, 16)
                
                self.vars[var_name].add(var_value)

            except Exception as e:
                print(f' 🤸🏻 Error while extracting observations from {var}. Skipping it.')
                print(e)
    
    def add_observation_with_type(self, vars):
        # This accepts a list of tuples, the first element specifies
        # the type of the value assigned to the variable.
        # e.g.,
        #   [("string", "arg1='jazze'"), ("int", "arg2=0x1234")]
        self.observations += 1
        for var in vars:
            var_type = var[0]
            var_data = var[1]
            try:
                var_name = var_data.split("=")[0]
                var_value = var_data.split("=")[1]

                if var_type == "numerical":
                    var_value = int(var_value, 16)
                elif var_type == "boolean":
                    var_value = bool(var_value)
                elif var_type == "string":
                    var_value = var_value

                self.vars[var_name].add(var_value)
            
            except Exception as e:
                print(f' 🤸🏻 Error while extracting observations from {var}. Skipping it.')
                print(e)

    def add_invariants(self, invs:set):
        '''
        Add an invariant to the program point.
        '''
        for inv in invs:
            self.invariants.add(inv)

    def get_vars_with_type(self, vtype:str) -> dict:
        '''
        Return all the variables belonging to this program
        point that has a certain type
           - vtype is in {str, int, bool}.
        '''
        vars_in_scope = {}

        if vtype not in ["numerical", 'boolean', 'string']:
            assert(False)

        if vtype == "numerical": vtype = int
        if vtype == "boolean": vtype = bool
        if vtype == "string": vtype = str

        for var_name, observations in self.vars.items():
            if observations.type == vtype:
                vars_in_scope[var_name] = observations

        return vars_in_scope


'''
             \     /
             \\   //
              )\-/(
              /e e\
             ( =Y= )
             /`-!-'\
        ____/ /___\ \
   \   /    ```    ```~~"--.,_
`-._\ /                       `~~"--.,_
----->|                                `~~"--.,_
_.-'/ \                                         ~~"--.,_
   /jgs\_________________________,,,,....----""""~~~~````

'''
class InvChecker:
    '''
    The Extractor is the class that is responsible for extracting invariants
    from a set of program points.
    '''
    def __init__(self, numerical_invs=True, boolean_invs=False, strings_invs=False):
        self.invariants = dict()

        if numerical_invs:
            self.invariants["numerical"] =  [
                                            NumericalUnaryNotZeroInvariant,
                                            NumericalUnaryConstantInvariant,
                                            NumericalUnaryMax,
                                            NumericalUnaryMin,
                                            NumericalBinaryXLessThanY,
                                            NumericalBinaryXGreaterThanY
                                            ]
        else:
            self.invariants["numerical"] = []

        
        if boolean_invs:
            self.invariants["boolean"]   =  [
                                            BooleanUnaryConstantInvariant
                                            ]
        else:
            self.invariants["boolean"] = []

        if strings_invs:
            self.invariants["string"]    =  [
                                            StringUnaryNotEmpty,
                                            StringUnaryConstant,
                                            StringUnaryMaxLength,
                                            StringUnaryValueInList
                                            ]
        else:
            self.invariants["string"] = []

    def extract(self, pps:dict):
        '''
        Given program points, we want to extract the invariants
        holding for their arguments.

        Stateful function:
            - This functions sets the invariants object for each program point.
        '''
            
        for p_name, p_info in pps.items():

            for inv_type, invs in self.invariants.items():
                # the inv_type is telling us which type of variables are in scope
                # the invs is a list of instances of Invariant classes for a specific variable type

                # let's extract all the variables in scope for this type
                vars_in_scope = p_info.get_vars_with_type(inv_type)

                if len(vars_in_scope.keys()) == 0:
                    # If there are no var in scope for this class, just
                    # go to next class
                    continue

                # Check all the available classes of invariants for this class
                for inv in invs:
                    res = inv.check(vars_in_scope)

                    if len(res) != 0:
                        # Storing the invariant in the program point
                        p_info.add_invariants(res)

    def check_violations(self, pps) -> dict:
            
        # For every program point with invariants
        inv_violations = {}
        ppts_unique_to_crash = []

        for p_name, p_info in pps.items():

            # Skip this program point if we have only one observation
            if p_info.observations == 1 and p_info.in_crashing_trace == True:
                # Interesting: this program point is unique to the crashing trace
                # we might want to output a separate report for this.
                
                print(f'{bcolors.WARNING}Program point {p_name} is unique to the crashing trace{bcolors.ENDC}')
                ppts_unique_to_crash.append(p_name)
                continue
                
            elif p_info.observations < MIN_OBSERVATIONS:
                # Skip this program point if we have less than MIN_OBSERVATIONS
                continue

            curr_invariants = set()

            for inv_type, invs in self.invariants.items():
                vars_in_scope = p_info.get_vars_with_type(inv_type)

                if len(vars_in_scope.keys()) == 0:
                    continue

                for inv in invs:
                    curr_invariants.update(inv.check(p_info.vars))
            
            broken_invariants = curr_invariants.difference(p_info.invariants)

            for broken_inv in broken_invariants:
                for prev_inv in p_info.invariants:
                    if broken_inv.is_comparable(prev_inv):
                        print(f' 😱 Invariant does not hold for program point {p_info.name}:')
                        print(f' - is: {bcolors.WARNING}{broken_inv}{bcolors.ENDC}')
                        print(f' - was: {bcolors.WARNING}{prev_inv}{bcolors.ENDC}')
                        if p_info.name not in inv_violations:
                            inv_violations[p_info.name] = []
                        inv_violations[p_info.name].append({'is': str(broken_inv), 'was': str(prev_inv)})
                            
        return inv_violations, ppts_unique_to_crash
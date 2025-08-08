/**
 * @kind path-problem
 */

 import cpp
 import semmle.code.cpp.dataflow.DataFlow

 module CallGraph {
   newtype TPathNode =
     TFunction(Function f) or
     TCall(Call c) or
     TGlobalVariable(GlobalVariable g) or
     TFunctionAccess(FunctionAccess c) or
     TVariableAccess(VariableAccess v) or
     TField(Field f) or
     TAssignment(Assignment a) or
     TInitializer(Initializer i)

   class PathNode extends TPathNode {
     Function asFunction() {
       this = TFunction(result)
       and not (
         result.getName() = "kthread_run"
       )
     }

     Call asCall() {
       this = TCall(result)
     }

     VariableAccess asVariableAccess() {
       this = TVariableAccess(result)
     }

     FunctionAccess asFunctionAccess() {
       this = TFunctionAccess(result)
     }

     Field asField() {
       this = TField(result)
       and not (
         // workqueues
         result.getDeclaringType().getName() = "worker"
         or
         result.getDeclaringType().getName() = "work_struct"
       )
     }

     GlobalVariable asGlobalVariable() {
       this = TGlobalVariable(result)
     }
     Assignment asAssignment() {
       this = TAssignment(result)
     }
     Initializer asInitializer() {
       this = TInitializer(result)
     }

     string toString() {
       result = this.asFunction().toString()
       or
       result = this.asCall().toString()
       or
       result = this.asGlobalVariable().toString()
       or
       result = this.asFunctionAccess().toString()
       or
       result = this.asVariableAccess().toString()
       or
       result = this.asField().toString()
       or
       result = this.asAssignment().toString()
       or
       result = this.asInitializer().toString()
     }

     string node_class() {
       // return the type of the node
       result = this.asFunction().getAPrimaryQlClass()
       or
       result = this.asCall().getAPrimaryQlClass()
       or
       result = this.asGlobalVariable().getAPrimaryQlClass()
       or
       result = this.asFunctionAccess().getAPrimaryQlClass()
       or
       result = this.asVariableAccess().getAPrimaryQlClass()
       or
       result = this.asField().getAPrimaryQlClass()
       or
       result = this.asAssignment().getAPrimaryQlClass()
       or
       result = this.asInitializer().getAPrimaryQlClass()
     }

     Location getLocation() {
       result = this.asFunction().getLocation()
       or
       result = this.asCall().getLocation()
       or
       result = this.asGlobalVariable().getLocation()
       or
       result = this.asFunctionAccess().getLocation()
       or
       result = this.asVariableAccess().getLocation()
       or
       result = this.asField().getLocation()
       or
       result = this.asAssignment().getLocation()
       or
       result = this.asInitializer().getLocation()
     }

     PathNode getASuccessor() {
       // link call to caller
       this.asFunction() = result.asCall().getEnclosingFunction()
       or
       // link call to callee
       (
         this.asCall().getTarget() = result.asFunction()
         and
         // the resulting function doesn't have too many callers
         count(Call c | c.getTarget() = result.asFunction()) <= 5
       )
       or
       // link function access to the function it references
       this.asFunctionAccess().getTarget() = result.asFunction()
       or
       // link function access to any global variables they're used in
       this.asGlobalVariable() = result.asFunctionAccess().getEnclosingVariable()
       or
       // link function access to any functions they're used in
       this.asFunction() = result.asFunctionAccess().getEnclosingFunction()
       or
       // link variable access to the global variable it's used in
       this.asGlobalVariable() = result.asVariableAccess().getEnclosingVariable()
       or
       // link variable access to the function it's used in
       this.asFunction() = result.asVariableAccess().getEnclosingFunction()
       or
       // We're storing something with the function pointer to
       exists(Assignment a, FieldAccess fa |
         // does the left-hand-side of the assignment have a modifying field access?
         a.getLValue() = fa and fa.isModified()
         and
         // and the right hand side has our function access?
         a.getRValue() = result.asFunctionAccess()
         and
         // then the field is one of our fields now
         fa.getTarget() = this.asField()
       )
       or
       // we're accessing the field in a function via reading, could be a call
       exists(FieldAccess fa |
         fa.getTarget() = result.asField()
         and
         not exists(Assignment a |
           a.getLValue() = fa // field access can't be in LHS of assignment
         )
         and not fa.isModified()
         and
         fa.getEnclosingFunction() = this.asFunction()
       )
       or
       exists(Assignment a, FieldAccess b |
         b.getTarget() = this.asField() // mark field accessed by b as belonging to us
         // if
         and
         // b's field is being assigned to
         a.getLValue() = b
         and
         // the assigned value is a field already under our control
         a.getRValue() = result.asField().getAnAccess()
       )
       // or
       // we're accessing the field in a function via reaimport semmle.code.cpp.dataflow.DataFlowding, could be a call
       // exists(FieldAccess fa |
       //   fa.getTarget() = result.asField()
       //   and
       //   result.asField().getName() = "encap_rcv"
       //   |
       //   Dataflow::localFlow(
       //     Dataflow::exprNode(

       //     )
       //   )
       // )
       // or
       // exists(ClassAggregateLiteral agglit, FieldAccess fa |
       //   // does the left-hand-side of the assignment have a modifying field access?
       //   agglit.
       // )
     }
   }

   query predicate edges(PathNode pred, PathNode succ) {
     pred.getASuccessor() = succ
   }
 }
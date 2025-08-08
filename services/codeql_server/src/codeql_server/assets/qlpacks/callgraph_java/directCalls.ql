import java

string callableType(Callable c) {
  c instanceof Method and result = "Method"
  or
  c instanceof Constructor and result = "Constructor"
  or
  c instanceof GeneratedCallable and result = "GeneratedCallable"
  or
  c instanceof GenericCallable and result = "GenericCallable"
  or
  c instanceof MetricCallable and result = "MetricCallable"
  or
  c instanceof SrcCallable and result = "SrcCallable"
  or
  c instanceof TestNGFactoryCallable and result = "TestNGFactoryCallable"
  or
  not c instanceof Method and
  not c instanceof TestNGFactoryCallable and
  not c instanceof Constructor and
  not c instanceof GeneratedCallable and
  not c instanceof GenericCallable and
  not c instanceof MetricCallable and
  not c instanceof SrcCallable and
  result = "OTHER"
}

string callType(Call c) {
  c instanceof ConstructorCall and result = "ConstructorCall"
  or
  c instanceof GenericCall and result = "GenericCall"
  or
  c instanceof MethodCall and result = "MethodCall"
  or
  not c instanceof ConstructorCall and
  not c instanceof GenericCall and
  not c instanceof MethodCall and
  result = "OTHER"
}

predicate invalidName(Callable c) {
  c.getName() = "<clinit>" //or c.getName() = ""
}

string getRealName(Callable c) {
  not invalidName(c) and result = c.getName()
  or
  invalidName(c) and result = getRealName(c.getEnclosingCallable())
}

boolean isVirtual(Call c) {
  c instanceof VirtualMethodCall and result = true
  or
  not c instanceof VirtualMethodCall and result = false
}

predicate isReal(Callable c){
  c.getLocation().getStartLine() != 0 and
  c.getLocation().getStartColumn() != 0 and
  c.getLocation().getEndLine() != 0 and
  c.getLocation().getEndColumn() != 0
}

from Callable src, Callable dst, Call call
where call.getEnclosingCallable() = src and call.getCallee() = dst //and call.getFile().getAbsolutePath().matches("%XMLReaderUtils%")
and isReal(dst)
select getRealName(src) as src_name, src.getLocation() as src_loc, getRealName(dst) as dst_name,
  dst.getLocation() as dst_loc, call.getLocation() as call_loc,
  isVirtual(call) as is_virtual,
  callType(call) as call_type

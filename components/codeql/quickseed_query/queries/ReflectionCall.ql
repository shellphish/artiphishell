import java
import semmle.code.java.Reflection

class MethodInvokeCall extends MethodCall {
  MethodInvokeCall() { this.getMethod().hasQualifiedName("java.lang.reflect", "Method", "invoke") or
   this.getMethod().hasQualifiedName("java.lang", "Class", "forName") or
   this.getMethod().hasQualifiedName("java.lang", "ClassLoader", "loadClass")
}
}


from MethodCall reflectionCall, Callable method
where
(
        reflectionCall.getMethod().hasQualifiedName("java.lang.reflect", "Constructor<>", "newInstance") or
        reflectionCall instanceof MethodInvokeCall
) and
reflectionCall.getEnclosingCallable() = method
select 
method as reflection_call_method_name, 
reflectionCall as undefined, 
method.getLocation() as reflection_call_method_location, 
reflectionCall.getLocation() as reflection_call_location

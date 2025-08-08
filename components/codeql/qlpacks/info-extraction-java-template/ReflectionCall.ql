import java
import semmle.code.java.Reflection

class MethodInvokeCall extends MethodCall {
  MethodInvokeCall() { this.getMethod().hasQualifiedName("java.lang.reflect", "Method", "invoke") or
   this.getMethod().hasQualifiedName("java.lang", "Class", "forName") or
   this.getMethod().hasQualifiedName("java.lang", "ClassLoader", "loadClass")
}
}


from MethodCall ma, Callable m
where
(
        ma.getMethod().hasQualifiedName("java.lang.reflect", "Constructor<>", "newInstance") or
        ma instanceof MethodInvokeCall
) and
ma.getEnclosingCallable() = m
select m, ma, m.getLocation(), ma.getLocation()
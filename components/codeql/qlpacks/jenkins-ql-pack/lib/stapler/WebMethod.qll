import java

import jenkins.ProductionCallable

class WebMethod extends Method, ProductionCallable {
    WebMethod() {
        // TODO make this nicer and more comprehensive, e.g. all parameters need to have one of several annotations or be one of several types

        // Stapler basic requirements for a method to be dispatchable
        // and include Jenkins DoActionFilter since 2.138.3
        this.isPublic()
        and
        not(this.hasAnnotation("jenkins.security.stapler", "StaplerNotDispatchable"))
        and
        (
            // Ensure the web method is properly annotated
            this.hasAnnotation("jenkins.security.stapler", "StaplerDispatchable")
            or
            this.hasAnnotation("org.kohsuke.stapler", "WebMethod")
            or
            this.getAnAnnotation().getType().hasAnnotation("org.kohsuke.stapler.interceptor", "InterceptorAnnotation")
            or
            this.getName().indexOf("do") = 0
        )
        and not exists(Parameter p | this.getAParameter() = p
            // Ensure no parameter exists without expected type or annotation
            and
            (
                not p.getType().hasName("StaplerRequest")
                and not p.getType().hasName("StaplerResponse")
                and not p.getType().hasName("HttpServletRequest")
                and not p.getType().hasName("HttpServletResponse")
                and not p.getType().hasName("ServletRequest")
                and not p.getType().hasName("ServletResponse")
                and not p.getType().hasName("RequestImpl")
                and not p.getType().hasName("ResponseImpl")
            )
            and not exists(Annotation a | p.getAnAnnotation() = a
                and
                (
                    a.getType().hasName("QueryParameter")
                    or
                    a.getType().hasName("AncestorInPath")
                    or
                    a.getType().hasName("Header")
                    or
                    a.getType().hasName("JsonBody")
                    or
                    a.getType().hasName("SubmittedForm")
                )
            )
        )
    }
}

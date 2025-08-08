import java

class NonTrivialInvocation extends Method {
    NonTrivialInvocation() {
        // TODO Add more stuff here that's safe
        not(
            this.hasName("length")
            or this.getDeclaringType().hasName("FormValidation")
            or this.getDeclaringType().hasName("Messages")
            or this.getDeclaringType().hasQualifiedName("org.apache.commons.lang", "StringUtils")
            or this.hasName("add") and this.getDeclaringType().hasQualifiedName("hudson.util", "ListBoxModel")
            or this.hasName("<init>") and this.getDeclaringType().hasQualifiedName("hudson.util", "ListBoxModel") // untested
        )
    }
}

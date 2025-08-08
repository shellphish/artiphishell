import java

class PermissionCheck extends Method {
    PermissionCheck() {
        (this.hasName("checkPermission") or this.hasName("hasPermission")) 
        and this.getNumberOfParameters() = 1
    }
}

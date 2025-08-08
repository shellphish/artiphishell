import hudson.security.AccessControlled;
import hudson.security.Permission;

public class HasPermissionReturnIgnored {
    public void thisIsWrong(AccessControlled ac) throws Exception {
        ac.hasPermission(Permission.READ);
    }

    public void thisIsOK(AccessControlled ac) throws Exception {
        if (!ac.hasPermission(Permission.READ)) {
            throw new Exception("prohibited!");
        }
    }

    public void thisIsAlsoOK(AccessControlled ac) throws Exception {
        ac.checkPermission(Permission.READ);
    }
}
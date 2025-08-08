import hudson.remoting.Callable;
import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;
import org.jenkinsci.remoting.RoleSensitive;
import jenkins.security.MasterToSlaveCallable;

public class BadRoleCheck {
    public static class OkCallable implements Callable {
        public void checkRoles(RoleChecker checker) throws SecurityException {
            checker.check(this, new Role("slave"));
        }
    }

    public static class StubCallable implements Callable {
        public void checkRoles(RoleChecker checker) throws SecurityException {
            // stub
        }
    }

    public static class WrongCallable implements Callable {
        public void checkRoles(RoleChecker checker) throws SecurityException {
            System.err.println("Hello, world!");
        }
    }

    public static class InheritedOkCallable extends MasterToSlaveCallable {
    }

    public static class InheritedOverrideCallable extends MasterToSlaveCallable {
        public void checkRoles(RoleChecker checker) throws SecurityException {
            // stub
        }
    }
}

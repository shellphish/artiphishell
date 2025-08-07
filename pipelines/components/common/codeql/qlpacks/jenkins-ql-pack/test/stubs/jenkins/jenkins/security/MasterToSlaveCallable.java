package jenkins.security;

import hudson.remoting.Callable;
import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;

public abstract class MasterToSlaveCallable implements Callable {
    @Override
    public void checkRoles(RoleChecker checker) throws SecurityException {
        checker.check(this, new Role("slave"));
    }
}

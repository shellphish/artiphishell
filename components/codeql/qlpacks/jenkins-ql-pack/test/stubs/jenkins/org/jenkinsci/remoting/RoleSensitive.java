package org.jenkinsci.remoting;

public interface RoleSensitive {
    void checkRoles(RoleChecker checker) throws SecurityException;
}

package org.jenkinsci.remoting;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

public abstract class RoleChecker {
    public RoleChecker() {
    }

    public abstract void check(RoleSensitive var1, Collection<Role> var2) throws SecurityException;

    public void check(RoleSensitive subject, Role expected) throws SecurityException {
        this.check(subject, (Collection)Collections.singleton(expected));
    }

    public void check(RoleSensitive subject, Role... expected) throws SecurityException {
        this.check(subject, (Collection)Arrays.asList(expected));
    }
}

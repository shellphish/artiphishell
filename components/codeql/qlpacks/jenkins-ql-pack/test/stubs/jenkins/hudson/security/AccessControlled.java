package hudson.security;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;

public interface AccessControlled {
    ACL getACL();

    default void checkPermission(Permission permission) throws AccessDeniedException {
        getACL().checkPermission(permission);
    }

    default void checkAnyPermission(Permission... permission) throws AccessDeniedException {
        getACL().checkAnyPermission(permission);
    }

    default boolean hasPermission(Permission permission) {
        return getACL().hasPermission(permission);
    }

    default boolean hasAnyPermission(Permission... permission) {
        return getACL().hasAnyPermission(permission);
    }

    default boolean hasPermission(Authentication a, Permission permission) {
        if (a == ACL.SYSTEM) {
            return true;
        }
        return getACL().hasPermission(a, permission);
    }

}
package hudson.security;

import org.acegisecurity.Authentication;

public class ACL {
    public static Authentication SYSTEM = new Authentication();

    public void checkPermission(Permission p) {
    }

    public final void checkAnyPermission(Permission... permissions) {
    }

    public final boolean hasPermission(Permission p) {
        return false;
    }

    public final boolean hasAnyPermission(Permission... permissions) {
        return false;
    }

    public /* abstract */ boolean hasPermission(Authentication a, Permission permission) {
        return false;
    }

    // public static ACL lambda(final BiFunction<Authentication, Permission, Boolean> impl) {
    //     return new ACL() {
    //         @Override
    //         public boolean hasPermission(Authentication a, Permission permission) {
    //             return impl.apply(a, permission);
    //         }
    //     };
    // }

}
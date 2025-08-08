package org.jenkinsci.remoting;

import java.util.Collection;
import java.util.Collections;

public final class Role {
    private final String name;
    public static final Role UNKNOWN = new Role("unknown");
    public static final Collection<Role> UNKNOWN_SET;

    public Role(String name) {
        this.name = name;
    }

    public Role(Class<?> name) {
        this(name.getName());
    }

    public String getName() {
        return this.name;
    }

    public String toString() {
        return super.toString() + "[" + this.name + "]";
    }

    public boolean equals(Object obj) {
        return obj instanceof Role && ((Role)obj).name.equals(this.name);
    }

    public int hashCode() {
        return this.name.hashCode();
    }

    static {
        UNKNOWN_SET = Collections.singleton(UNKNOWN);
    }
}

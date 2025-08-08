package hudson.security;

public final class Permission {
    public static final Permission READ = new Permission();
    public static final Permission WRITE = new Permission();
    public static final Permission CREATE = new Permission();
    public static final Permission UPDATE = new Permission();
    public static final Permission DELETE = new Permission();
    public static final Permission CONFIGURE = new Permission();
}

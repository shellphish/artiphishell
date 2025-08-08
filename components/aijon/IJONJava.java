import com.code_intelligence.jazzer.api.Jazzer;

public class IJONJava {
    private static StackTraceElement getFirstExternalCaller() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement element : stack) {
            String className = element.getClassName();

            // Skip internal utility, reflection, and threading infrastructure
            // System.out.println("Checking element: " + element);
            if (!className.equals(IJONJava.class.getName()) &&
                !className.startsWith("java.lang.reflect.") &&
                !className.equals(Thread.class.getName())) {
                return element;
            }
        }
        // Fallback
        return new StackTraceElement("UnknownClass", "unknownMethod", "UnknownFile", -1);
    }

    public static int getCurrentLineNumber() {
        return getFirstExternalCaller().getLineNumber();
    }

    public static String getCurrentFileName() {
        return getFirstExternalCaller().getFileName();
    }

    public static int IJONHashState() {
        int lineNumber = getCurrentLineNumber();
        String fileName = getCurrentFileName();
        if (fileName == null) {
            // System.out.println("Falling back to UnknownFile");
            fileName = "UnknownFile";
        }
        return fileName.hashCode() ^ lineNumber;
    }

    public static int IJONHash(int value) {
        return value ^ getCurrentLineNumber();
    }

    public static void IJON_CTX(int ctx_num) {
        // System.out.println("IJON_CTX called with value: " + ctx_num);
        Jazzer.exploreState((byte)(ctx_num & 0xFF), IJONHashState());
    }

    public static void IJON_SET(int value) {
        // System.out.println("IJON_SET called with value: " + value);
        Jazzer.markCoverage(IJONHash(value));
    }

    public static void IJON_INC(int value) {
        // System.out.println("IJON_INC called with value: " + value);
        Jazzer.markCoverage(IJONHash(value));
    }

    public static void IJON_CMP(long value, long cmp_value) {
        // System.out.println("IJON_CMP: " + value + " -> " + cmp_value);
        Jazzer.guideTowardsEquality(value, cmp_value, IJONHashState());
    }

    public static void IJON_CMP(int value, int cmp_value) {
        // System.out.println("IJON_CMP: " + value + " -> " + cmp_value);
        Jazzer.guideTowardsEquality(value, cmp_value, IJONHashState());
    }

    public static void IJON_DIST(long value, long target) {
        // System.out.println("IJON_DIST: " + value + " -> " + target);
        Jazzer.guideTowardsEquality(value, target, IJONHashState());
    }

    public static void IJON_DIST(int value, int target) {
        // System.out.println("IJON_DIST: " + value + " -> " + target);
        Jazzer.guideTowardsEquality(value, target, IJONHashState());
    }

    public static void IJON_STRDIST(String str, String target) {
        // System.out.println("IJON_STRDIST: " + str + " -> " + target);
        Jazzer.guideTowardsEquality(str, target, IJONHashState());
    }

    public static void IJON_MAX(long value) {
        // System.out.println("IJON_MAX: " + value + " -> " + Long.MAX_VALUE);
        Jazzer.guideTowardsEquality(value, Long.MAX_VALUE, IJONHashState());
    }

    public static void IJON_MAX(int value) {
        // System.out.println("IJON_MAX: " + value + " -> " + Integer.MAX_VALUE);
        Jazzer.guideTowardsEquality(value, Integer.MAX_VALUE, IJONHashState());
    }

    public static void IJON_MIN(long value) {
        // System.out.println("IJON_MIN: " + value + " -> " + Long.MIN_VALUE);
        Jazzer.guideTowardsEquality(value, Long.MIN_VALUE, IJONHashState());
    }

    public static void IJON_MIN(int value) {
        // System.out.println("IJON_MIN: " + value + " -> " + Integer.MIN_VALUE);
        Jazzer.guideTowardsEquality(value, Integer.MIN_VALUE, IJONHashState());
    }
}

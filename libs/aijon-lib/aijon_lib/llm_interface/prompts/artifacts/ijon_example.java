import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import java.lang.reflect.Method;


public class IJONDemo {

    // Global previous value tracker for IJON_INC simulation
    private static int prevX = Integer.MIN_VALUE;

    public static void do_main(byte[] data) {
        if (data.length < 12) return;

        // Extract integers and a string from the fuzz input
        int x = getInt(data, 0);
        int a = getInt(data, 4);
        int b = getInt(data, 8);
        String s = new String(data, 12, data.length - 12, StandardCharsets.UTF_8);

        // (2) IJON_ASSUME-like behavior: skip all x >= 0
        if (x >= 0) return;

        // (3) IJON_INC: reward new x values
        if (x != prevX) {
            Class.forName("IJONJava")
                 .getMethod("IJON_INC", int.class)
                 .invoke(null, x);
            prevX = x;
        }

        // (3) IJON_SET: mark unique values of x
        Class.forName("IJONJava")
             .getMethod("IJON_SET", int.class)
             .invoke(null, x);

        // (4) IJON_CTX: encode control-flow context based on x parity
        if (x % 2 == 0) {
            Class.forName("IJONJava")
                 .getMethod("IJON_CTX", int.class)
                 .invoke(null, 1); // even
        } else {
            Class.forName("IJONJava")
                 .getMethod("IJON_CTX", int.class)
                 .invoke(null, 2); // odd
        }

        // Simulate behavior that depends on the current context
        checkComplexCondition(a, b);

        // (5) IJON_CMP: reward bit-wise similarity to magic constants
        Class.forName("IJONJava")
             .getMethod("IJON_CMP", int.class, int.class)
             .invoke(null, x, 0xDEADBEEF);

        Class.forName("IJONJava")
             .getMethod("IJON_CMP", int.class, int.class)
             .invoke(null, x, 0xC0DECAFE);

        if (x == 0xDEADBEEF) {
            System.out.println("Secret unlocked!");
        } else if (x == 0xC0DECAFE) {
            System.out.println("Secret 2 unlocked!");
        }

        // (6) IJON_DIST: reward inputs that bring (a + b) closer to 1000
        Class.forName("IJONJava")
             .getMethod("IJON_DIST", int.class, int.class)
             .invoke(null, a + b, 1000);

        if ((a + b) == 1000) {
            System.out.println("Reached target sum.");
        }

        // (7) IJON_STRDIST: reward inputs that approach "OPEN" string
        Class.forName("IJONJava")
             .getMethod("IJON_STRDIST", String.class, String.class)
             .invoke(null, s, "OPEN");

        if (s.equals("OPEN")) {
            System.out.println("Opened!");
        }

        // (8) IJON_MAX: maximize score computed from input string
        long score = computeScore(s);
        Class.forName("IJONJava")
             .getMethod("IJON_MAX", long.class)
             .invoke(null, score);

        // (8) IJON_MIN: minimize difference between a and b
        Class.forName("IJONJava")
             .getMethod("IJON_MIN", long.class)
             .invoke(null, (long)Math.abs(a - b));
    }

    private static void checkComplexCondition(int a, int b) {
        if ((a ^ b) == 0x12345678) {
            System.out.println("Check passed.");
        }
    }

    private static long computeScore(String s) {
        return Arrays.stream(s.split(""))
                     .mapToInt(c -> c.isEmpty() ? 0 : c.charAt(0))
                     .sum();
    }

}
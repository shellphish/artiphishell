public class UnsafeCalls {
    public void bad() throws Exception {
        Runtime.getRuntime().exec("bad");
    }
}

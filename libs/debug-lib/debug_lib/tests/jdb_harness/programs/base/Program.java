// Your First Program
class Program {
   public Boolean d = true;
   
   public void innerFunction(String arg1, String argv[]) {
      Object o = new Object();
      int a = Integer.parseInt(argv[0]);
      System.out.println("A : " + a);
      int b = Integer.parseInt(argv[1]);
      System.out.println("B : " + b);
      int c = a + b;
      System.out.println("C = a + b : " + c);
      System.out.println(arg1);
      System.out.println(o);
      this.d = false;
    }

   public static void main(String argv[]) {
      String outstr = "Hello World!";
      Program prog = new Program();
      prog.innerFunction(outstr, argv);
      System.out.println("D Value = " + prog.d);
   }

}

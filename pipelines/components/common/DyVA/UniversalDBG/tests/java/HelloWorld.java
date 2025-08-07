// Your First Program
class HelloWorld {
public static void main(String argv[])
   {
      String outstr = "Hello World!";
      Boolean d = true;
      Object o = new Object();
      int a = Integer.parseInt(argv[0]);
      System.out.println("A : " + a);
      int b = Integer.parseInt(argv[1]);
      System.out.println("B : " + b);
      int c = a + b;
      System.out.println("C = a + b : " + c);
      System.out.println(outstr);
      System.out.println(o);
      System.out.println(d);
   }

}

import java.io.{File => JFile, PrintWriter}

@main def main(inputFilePath: String, outputFilePath: String): Unit = {
  importCode(inputPath=inputFilePath, projectName="harness-c")

  val sb = new StringBuilder

  val external = cpg.method.filter(_.isExternal).filterNot(_.name.startsWith("<operator>")).name.toSet

  def source = cpg.method.name("main").parameter

  external.foreach { ext =>
    println(ext)
    val calls = cpg.call.name(ext)
    val arguments = calls.flatMap(_.argument)
    arguments.foreach { arg =>
      println(arg)
      println(arg.reachableBy(source).toList)
      if (arg.reachableBy(source).toList.length > 0) {
        sb.append(s"${ext}:${arg.argumentIndex-1}\n")
      }
    }
  }

  val pw = new PrintWriter(new JFile(outputFilePath))
  pw.write(sb.toString)
  pw.close()
}

import java.io.{File => JFile, PrintWriter}

@main def main(inputFilePath: String, outputFilePath: String): Unit = {
  importCode(inputPath=inputFilePath, projectName="harness-c")

  val sb = new StringBuilder

  val external = cpg.method.filter(_.isExternal).filterNot(_.name.startsWith("<operator>")).name.toSet
  println(s"${external}")
  external.foreach { ext =>
    sb.append(s"${ext}\n")
  }

  val pw = new PrintWriter(new JFile(outputFilePath))
  pw.write(sb.toString)
  pw.close()
}

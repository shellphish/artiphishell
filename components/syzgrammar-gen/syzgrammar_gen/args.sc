import java.io.{File => JFile, PrintWriter}
import scala.io.Source

@main def main(inputFilePath: String, outputFilePath: String): Unit = {
  importCode(inputPath = inputFilePath, projectName = "harness-c")

  val filePath = "./externs"
  val external = Source.fromFile(filePath).getLines().toList

  // Helper function to escape special characters in JSON strings
  def escapeJsonString(str: String): String = {
    str.flatMap {
      case '"'  => "\\\""  // Escape double quote
      case '\\' => "\\\\"  // Escape backslash
      case '\b' => "\\b"   // Escape backspace
      case '\f' => "\\f"   // Escape form feed
      case '\n' => "\\n"   // Escape newline
      case '\r' => "\\r"   // Escape carriage return
      case '\t' => "\\t"   // Escape tab
      case c if c.isControl => "\\u%04x".format(c.toInt)  // Escape other control characters
      case c => c.toString  // Keep other characters as is
    }
  }

  val sb = new StringBuilder
  sb.append("[\n")  // Start of JSON array

  var first = true  // To manage commas between JSON objects

  external.foreach { ext =>
    var call_name = ext
    var arg_adjust = 1
    var calls = cpg.call.name(call_name)

    if (call_name.trim == "syscall") {
      arg_adjust = 2
    }

    calls.toList.foreach { call =>
      if (call.name.trim == "syscall") {
        val syscall_num_arg = call.argument(1)
        if (syscall_num_arg.isLiteral) {
          call_name = s"syscall#${syscall_num_arg.code}"
        } else {
          println(s"WARN: First argument of syscall() was not a literal -- ${syscall_num_arg.code}!")
        }
      }
      call.argument.foreach { arg =>
        val argIndex = arg.argumentIndex - arg_adjust
        if (argIndex >= 0) {
          if (!first) {
            sb.append(",\n")  // Add a comma before the next JSON object
          }
          first = false  // Set to false after the first object is added

          // Prepare JSON fields with proper escaping
          val callNameJson = escapeJsonString(call_name)
          val isLiteralJson = arg.isLiteral
          val codeJson = escapeJsonString(arg.code)

          // Build the JSON object
          sb.append("  {\n")
          sb.append(s"""    "callName": "$callNameJson",\n""")
          sb.append(s"""    "argumentIndex": $argIndex,\n""")
          sb.append(s"""    "isLiteral": $isLiteralJson""")
          sb.append(s""",\n    "code": "$codeJson"\n""")
          sb.append("  }")
        }
      }
    }
  }

  sb.append("\n]\n")  // End of JSON array

  val pw = new PrintWriter(new JFile(outputFilePath))
  pw.write(sb.toString)
  pw.close()
}


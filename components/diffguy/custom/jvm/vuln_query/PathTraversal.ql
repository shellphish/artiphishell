
/**
 * @id java/CommandInjection
 * @kind problem
 * @name List all function calls in paths related to source and target functions
 * @severity information
 */

import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions

// Base predicate for direct calls
predicate edges(Callable pred, Callable succ) {
  pred.polyCalls(succ) and
  succ.getName() != ""
}
predicate is_target_function(Callable c) {

     c.getQualifiedName().matches("java.nio.file.Files.newBufferedReader")

     or c.getQualifiedName().matches("java.nio.file.Files.newByteChannel")

     or c.getQualifiedName().matches("java.nio.file.Files.readString")

     or c.getQualifiedName().matches("java.nio.file.Files.newBufferedWriter")

     or c.getQualifiedName().matches("java.nio.file.Files.readAllBytes")

     or c.getQualifiedName().matches("java.nio.file.Files.readAllLines")

     or c.getQualifiedName().matches("java.nio.file.Files.readSymbolicLink")

     or c.getQualifiedName().matches("java.nio.file.Files.write")

     or c.getQualifiedName().matches("java.nio.file.Files.writeString")

     or c.getQualifiedName().matches("java.nio.file.Files.newInputStream")

     or c.getQualifiedName().matches("java.nio.file.Files.newOutputStream")

     or c.getQualifiedName().matches("java.nio.channels.FileChannel.open")

     or c.getQualifiedName().matches("java.nio.file.Files.copy")

     or c.getQualifiedName().matches("java.nio.file.Files.move")

     or c.getQualifiedName().matches("java.nio.file.Path.resolve")

     or c.getQualifiedName().matches("java.io.FileReader.FileReader")

     or c.getQualifiedName().matches("java.io.FileWriter.FileWriter")

     or c.getQualifiedName().matches("java.io.FileInputStream.FileInputStream")

     or c.getQualifiedName().matches("java.io.FileOutputStream.FileOutputStream")

     or c.getQualifiedName().matches("java.util.Scanner.Scanner")

}

predicate target_reachable(Callable c) {
  is_target_function(c) or
  exists(Callable next | target_reachable(next) and edges(c, next))
}


from Callable prevcall, Callable inbetween, Callable dest, Call tcall
where
  // Must have a valid call relationship
  prevcall.polyCalls(inbetween) and
  tcall = prevcall.getACallSite(inbetween) and

  // At least one of these must be true to be interesting
  (
    target_reachable(inbetween)
  )
  and
  is_target_function(dest)

// select src as entryPoint, src.getLocation() as entryPointId, dst as end, dst.getLocation() as endId

select
inbetween.getLocation() as id,
inbetween.getQualifiedName() as name,
dest.getQualifiedName() as note
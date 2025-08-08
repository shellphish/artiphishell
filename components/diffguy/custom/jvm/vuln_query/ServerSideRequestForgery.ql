
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

     c.getQualifiedName().matches("java.net.Socket")

     or c.getQualifiedName().matches("java.net.SocketImpl")

     or c.getQualifiedName().matches("java.net.SocksSocketImpl")

     or c.getQualifiedName().matches("java.nio.channels.SocketChannel.connect")

     or c.getQualifiedName().matches("sun.nio.ch.SocketAdaptor")

     or c.getQualifiedName().matches("jdk.internal.net.http.PlainHttpConnection")

     or c.getQualifiedName().matches("java.net.http.HttpClient.send")

     or c.getQualifiedName().matches("java.net.http.HttpClient.sendAsync")

     or c.getQualifiedName().matches("java.net.URL.openConnection")

     or c.getQualifiedName().matches("java.net.URL.openStream")

     or c.getQualifiedName().matches("java.net.URLConnection.connect")

     or c.getQualifiedName().matches("java.net.URLConnection.getInputStream")

     or c.getQualifiedName().matches("java.net.HttpURLConnection.getResponseCode")

     or c.getQualifiedName().matches("java.net.HttpURLConnection.getInputStream")

     or c.getQualifiedName().matches("java.net.HttpURLConnection.getOutputStream")

     or c.getQualifiedName().matches("java.net.URLConnection.getContent")

     or c.getQualifiedName().matches("java.sql.DriverManager.getConnection")

     or c.getQualifiedName().matches("javax.xml.parsers.DocumentBuilder.parse")

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
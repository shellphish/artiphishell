/**
 * @name Result of hasPermission call is ignored
 * @description The result of a #hasPermission call is ignored, indicating a missing permission check: It should either be a call to #checkPermission, or the return value should not be ignored
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id jenkins/has-permission-return-value-ignored
 * @tags security
 *       external/cwe/cwe-862
 */

import java

from MethodAccess unchecked, Method m
where unchecked.getMethod() = m and m.hasName("hasPermission")
  and unchecked.getParent() instanceof ExprStmt
select unchecked, "The result of the call is ignored"

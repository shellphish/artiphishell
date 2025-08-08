/**
 * @name Stapler: Missing permission check
 * @description A Stapler web method does not perform a permission check.
 *              This can be problem if the method returns private information, or has side effects.
 *              See the documentation: https://www.jenkins.io/doc/developer/security/form-validation/
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id jenkins/no-permission-check
 * @tags security
 *       external/cwe/cwe-862
 */

import java
import jenkins.NonTrivialInvocation
import jenkins.PermissionCheck
import stapler.WebMethod

from WebMethod m
where
    not exists(PermissionCheck c | m.polyCalls*(c)) and
    exists (NonTrivialInvocation t | m.polyCalls+(t))
select m, "Potential missing permission check in " + m.getDeclaringType().getName() + "#" + m.getName()

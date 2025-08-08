/**
 * @id non-init-calls-init
 * @kind problem
 * @description Find functions not annotated with __init (or similar) which call
 * __init-annotated functions. These instances are potential bugs.
 *
 * Examples:
 *  - https://stackoverflow.com/a/70823863/3889449
 *  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=45967ffb9e50aa3472cc6c69a769ef0f09cced5d
 *  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5f117033243488a0080f837540c27999aa31870e
 */

import cpp
import utils

from KernelFunc initFunc, KernelFunc caller
where
	(initFunc.isInSection(".init.text") or initFunc.isInSection(".head.text"))
	and caller = initFunc.getACallToThisFunction().getEnclosingFunction()
	and not caller.isInline()
	and not caller.isInSection(".init.text")
	and not caller.isInSection(".ref.text")
	and not caller.isInSection(".head.text")
select
	caller, "non-init function calls init function " + initFunc.getName()

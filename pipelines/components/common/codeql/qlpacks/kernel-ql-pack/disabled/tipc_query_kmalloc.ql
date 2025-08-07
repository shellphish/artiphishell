/**
 * @id kernel-kmalloc-argument-is-16-bit
 * @kind problem
 */

// https://www.sentinelone.com/labs/tipc-remote-linux-kernel-heap-overflow-allows-arbitrary-code-execution/

import cpp

from FunctionCall fc // Select all Function Calls
where fc.getTarget().getName() = "kmalloc" // Where the target function is called kmalloc
and fc.getArgument(0).getType().getSize() = 2 // and the supplied size argument is a 16-bit int
select fc, "kmalloc called with 16-bit size argument"

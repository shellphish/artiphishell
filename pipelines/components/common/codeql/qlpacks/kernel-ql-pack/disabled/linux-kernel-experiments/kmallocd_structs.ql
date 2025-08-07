/**
 * @id kmallocd-structs
 * @kind problem
 * @description Find out all structs that are ever kfree'd at least once (and where) and
 * their corresponding kmalloc slab size. Useful for use-after-free scenarios.
 */

 import cpp
 import utils
 
 from FunctionCall f, Struct s
 where
   f.getTarget().hasName("kmalloc") and
   (
	 exists(Initializer i, DeclarationEntry d, PointerType p |
	   i = f.getParent() and d = i.getDeclaration().getADeclarationEntry() and p = d.getType() and s = p.getBaseType().getUnspecifiedType()
	 )
	 or
	 exists(AssignExpr a, PointerType p |
	   a = f.getParent() and p = a.getType() and s = p.getBaseType().getUnspecifiedType()
	 )
   )
select
  f, "kmalloc'd struct " + s.getName() + " (size: " + s.getSize() + ", slab: " + kmallocSlab(s.getSize()) + ")"
 
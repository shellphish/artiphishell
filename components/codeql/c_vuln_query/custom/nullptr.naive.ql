import cpp

from VariableAccess access
where
  maybeNull(access) and
  dereferenced(access)
select access, "Value may be null; it should be checked before dereferencing." as note, access.getEnclosingFunction().getLocation() as id,
access.getEnclosingFunction().getName() as name
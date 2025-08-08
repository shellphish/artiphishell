import java
 
from Method m
where m.fromSource()
select m.getQualifiedName() as source_qualified_name

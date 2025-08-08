import java

from Method dst
where not dst.getDeclaringType() instanceof Interface
// and not exists(LambdaExpr lambda | lambda.asMethod() = dst)
select dst.getName() as name, dst.getLocation() as loc, dst.getSignature() as param

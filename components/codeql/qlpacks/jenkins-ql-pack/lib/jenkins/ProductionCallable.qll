import java

class ProductionCallable extends Callable {
    ProductionCallable() {
        this.fromSource()
        and (
            this.getCompilationUnit().getAbsolutePath().indexOf("src/main/java") != -1
            or // support QL test sources
            this.getCompilationUnit().getAbsolutePath().indexOf("test/query-tests") != -1
        )
    }
}

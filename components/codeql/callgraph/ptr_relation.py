from libcodeql.client import CodeQLClient

client = CodeQLClient()

class BaseRelationQuerySet:
    def __init__(self, project_id, db_name, use_cache=True):
        self.DB_NAME = db_name
        self.PROJ_ID = project_id
        self.USE_CACHE = use_cache
        self.querie_sets = []
        self.query_template = ""

    def query(self, result_set=None):
        if result_set not in self.querie_sets:
            raise ValueError(
                f"Invalid result_set: {result_set}. Must be one of {self.querie_sets}"
            )
        if not self.query_template:
            raise ValueError("Query template is not set.")
        return client.query(
            {
                "cp_name": self.DB_NAME,
                "project_id": self.PROJ_ID,
                "query_tmpl": f"{self.query_template}_{result_set}.ql",
                "query_params": {"foo": "bar"},
                "result_set": result_set,
                "entities": "all",
            }
        )

class FunctionPointerRelation(BaseRelationQuerySet):
    def __init__(self, project_id, db_name, use_cache=True):
        super().__init__(project_id, db_name, use_cache)
        self.query_template = "callgraph_c/funcPtrInfo"
        self.querie_sets = [
            "enclosingVar",
            "enclosingGVar",
            "enclosingFunc",
            "enclosingElem",
            "enclosingStmt",
            "enclosingDecl",
            "enclosingBlk",
        ]

class GlobalVariableRelation(BaseRelationQuerySet):
    def __init__(self, project_id, db_name, use_cache=True):
        super().__init__(project_id, db_name, use_cache)
        self.query_template = "callgraph_c/GVPtrInfo"
        self.querie_sets = [
            "enclosingVar",
            "enclosingGVar",
            "enclosingFunc",
            "enclosingElem",
            "enclosingStmt",
            "enclosingDecl",
            "enclosingBlk",
        ]
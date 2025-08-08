from pathlib import Path
from typing import List, Optional
import subprocess

from .client import QueryServerClient, ProgressCallback
from .messages import RunQueryParams, RunQueryResult, CompilationTarget, QueryResultType

class QueryRunner:
    def __init__(self, client: QueryServerClient):
        self.client = client
        
    async def register_databases(self, databases: List[Path]) -> None:
        """Register databases with the query server"""
        await self.client.register_databases([str(db.resolve()) for db in databases])
        
    async def run_query(self,
                       db_path: Path,
                       query_path: Path,
                       output_path: Path,
                       additional_packs: List[Path] = None,
                       progress_callback: Optional[ProgressCallback] = None,
                       task_id: str = None,
                       timeout: Optional[int] = None
                       ) -> RunQueryResult:

        # Ensure absolute paths
        db_path = db_path.resolve()
        query_path = query_path.resolve()
        output_path = output_path.resolve()
        
        # Ensure database is registered first
        await self.register_databases([db_path])
        
        params = RunQueryParams(
            query_path=str(query_path),
            output_path=str(output_path),
            db=str(db_path),
            additional_packs=[str(p) for p in (additional_packs or [])],
            target=CompilationTarget(query={}),
            external_inputs={},
            singleton_external_inputs={}
        )

        result = await self.client.send_request(
            "evaluation/runQuery",
            params,
            progress_callback=progress_callback,
            request_id=task_id,
            timeout=timeout
        )

        return RunQueryResult(
            result_type=QueryResultType(result["resultType"]),
            message=result.get("message"),
            evaluation_time=result["evaluationTime"]
        )

    async def bqrs_to_csv(self, bqrs_path: Path, output_path: Path, result_set: str | None, entities: str | None):
        # codeql bqrs decode --format csv bqrs_path --output output_path
        cmd = ["codeql", "bqrs", "decode", "--format", "csv", str(bqrs_path), "--output", str(output_path)]
        if result_set:
            cmd += ["--result-set", result_set]
        if entities:
            cmd += ["--entities", entities]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to convert bqrs to csv: {result.stderr}")


    async def clear_cache(self, db_path: Path) -> str:
        result = await self.client.send_request(
            "evaluation/clearCache",
            {
                "db": str(db_path),
                "dryRun": False
            }
        )
        return result["deletionMessage"]


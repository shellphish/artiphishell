import os
import json
from typing import List, Tuple
import jinja2
import asyncio
import pathlib
from libcodeql.client import CodeQLClient
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.models.symbols import SourceLocation
from pathlib import Path

SCRIPT_PATH = pathlib.Path(__file__).parent.resolve()
CACHE_DIR = pathlib.Path(__file__).parent.resolve()

client = CodeQLClient()


class Analyzer:
    def __init__(
        self,
        project_id,
        db_name,
        ql_path=str(SCRIPT_PATH),
        use_cache=True,
    ):
        self.DB_NAME = db_name
        self.PROJ_ID = project_id
        self.QL_PATH = ql_path
        self.USE_CACHE = use_cache

    def _readQueryRecursive(self, path):
        all_queries = []
        for root, dirs, files in os.walk(f"{self.QL_PATH}/{path}"):
            for file in files:
                if file.endswith(".ql"):
                    all_queries.append(os.path.join(root, file))
                elif os.path.isdir(os.path.join(root, file)):
                    sub = self._readQueryRecursive(os.path.join(root, file))
                    all_queries += sub
        return all_queries

    def _run_query(
        self, query_file=None, query_string=None, result_set=None, entities=None
    ):
        query = query_string
        if not query_file and not query_string:
            raise Exception("No query to run")
        if not query_string:
            with open(query_file, "r") as qf:
                query = qf.read()
        return client.query(
            {
                "cp_name": self.DB_NAME,
                "project_id": self.PROJ_ID,
                "query": query,
                "result_set": result_set,
                "entities": entities,
            }
        )

    async def _run_query_group(self, group, aggregate=True):
        all_queries = self._readQueryRecursive(group)
        tasks = []
        keys = []
        for i, query in enumerate(all_queries):
            try:
                keys.append(query)
                res = await asyncio.create_task(self._run_query(query_file=query))
                tasks.append(res)
            except Exception as e:
                if artiphishell_should_fail_on_error():
                    raise
                print("Error running query", query, ":", e)
                tasks.append([])
        # r = await asyncio.gather(*tasks)
        r = tasks

        for key, res in zip(keys, r):
            print("Query", key, "returned", len(res), "results.")

        if not aggregate:
            return {k: v for k, v in zip(keys, r)}

        res = [
            {
                **a,
                "query": query,
            }
            for row, query in zip(r, keys)
            for a in row
        ]

        # with open("DEBUG.json", "w") as f:
        #     json.dump(res, f, indent=4)

        # res = r

        # New format discussed with Fabio
        new_format = {}
        for r in res:
            try:
                if "id" not in r:
                    continue
                if r["id"] not in new_format:
                    parts = r["id"].split(":")
                    new_format[r["id"]] = {
                        "id": r["id"],
                        "name": r["name"],
                        "src": "codeql",
                        "location": SourceLocation(
                            full_file_path=Path(parts[1]),
                            file_name=Path(parts[1]).name,
                            line_number=int(parts[2]),
                            function_name=r["name"],
                        ).model_dump(mode="json"),
                        "hits": [],
                        # "file_name": ":".join(r["id"][len("file://") :].split(":")[:-4]),
                        # "function_name": r["name"],
                        # "line": [],
                        # "reason": [],
                    }
                parts = r["access"].split(":")
                start_line = parts[2]
                end_line = parts[4]
                lines = f"{start_line}-{end_line}" if start_line != end_line else start_line
                try:
                    t = r["query"].split("/")[-1].split(".ql")[0]
                except Exception as e:
                    print("warning: failed to split query type")
                    t = r["query"]
                new_format[r["id"]]["hits"].append(
                    {
                        "type": t,
                        "query": r["query"],
                        "desc": r["note"],
                        "endLine": start_line,
                        "startLine": end_line,
                        "location": SourceLocation(
                            full_file_path=Path(parts[1]),
                            file_name=Path(parts[1]).name,
                            line_number=start_line,
                        ).model_dump(mode="json"),
                        "additionalInfo": {"access": r["access"]},
                    }
                )
                # new_format[r["id"]]["line"].append(lines)
                # new_format[r["id"]]["reason"].append(r["note"])
            except Exception as e:
                if artiphishell_should_fail_on_error():
                    raise
                print("Error processing result for query", r["query"], ":", e)

        new_format = [new_format[k] for k in new_format.keys()]
        return new_format

    def run_query_group(self, group, aggregate=True):
        return asyncio.run(self._run_query_group(group, aggregate=aggregate))

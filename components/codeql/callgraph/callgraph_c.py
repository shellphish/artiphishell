import os
import json
from typing import List, Tuple
import jinja2
import asyncio
import pathlib
from libcodeql.client import CodeQLClient
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error

CACHE_DIR = pathlib.Path(__file__).parent.resolve()

client = CodeQLClient()


class BetterCallGraph:
    def __init__(
        self,
        project_id,
        db_name,
        use_cache=True,
    ):
        self.DB_NAME = db_name
        self.PROJ_ID = project_id
        self.USE_CACHE = use_cache

        # self.direct = self._getReachability("reachable.ql", includeParam=True)
        self.fptrac = self._getReachability("funcPtrAccesses.ql", includeParam=True)
        self.allfun = self._getReachability("allFuncs.ql", includeParam=True)
        self.calls = self._getReachableEdges("directCalls.ql")
        self.calledby = self._getReachableEdges("directCalls.ql", reverse=True)
        self.exprcalls, self.exprcalledby = self._parseExprCalls()

    def _getReachability(
        self, queryFile, includeParam=False
    ):  # Note: exprCall will give all callable pointers, which has a huge false positive rate
        if os.path.exists(f"{CACHE_DIR}/cache_{queryFile}.json") and self.USE_CACHE:
            with open(f"{CACHE_DIR}/cache_{queryFile}.json") as f:
                return json.load(f)
        res = client.query(
            {
                "cp_name": self.DB_NAME,
                "project_id": self.PROJ_ID,
                "query_tmpl": f"callgraph_c/{queryFile}",
                "query_params": {"foo": "bar"},
            }
        )
        if not includeParam:
            res = {f["loc"]: f["name"] for f in res}
        else:
            res = {
                f["loc"]: {
                    **f,
                    "name": f["name"],
                    "param": [
                        " ".join(a.strip().split(" ")[:-1])
                        for a in f["param"].split(",")
                    ],
                }
                for f in res
            }
        if self.USE_CACHE:
            with open(f"{CACHE_DIR}/cache_{queryFile}.json", "w") as f:
                json.dump(res, f)
        return res

    def get_all_callers(self):
        res = {}
        for f in self.calledby:
            if f not in res:
                res[f] = []
            res[f] += self.calledby[f]
        for f in self.exprcalledby:
            if f not in res:
                res[f] = []
            res[f] += self.exprcalledby[f]
        return res

    def get_all_callees(self):
        res = {}
        for f in self.calls:
            if f not in res:
                res[f] = []
            res[f] += self.calls[f]
        for f in self.exprcalls:
            if f not in res:
                res[f] = []
            res[f] += self.exprcalls[f]
        return res

    def _directoryDifference(self, id1, id2):
        return abs(len(id1.split("/")) - len(id2.split("/"))) + len(
            [
                1
                for a, b in zip(
                    id1.split(":")[1].split("/"),
                    id2.split(":")[1].split("/"),
                )
                if a != b
            ]
        )

    def _getReachableEdges(self, queryFile, reverse=False):
        if (
            os.path.exists(f"{CACHE_DIR}/cache_{queryFile}_{reverse}.json")
            and self.USE_CACHE
        ):
            with open(f"{CACHE_DIR}/cache_{queryFile}_{reverse}.json") as f:
                return json.load(f)
        qry = client.query(
            {
                "cp_name": self.DB_NAME,
                "project_id": self.PROJ_ID,
                "query_tmpl": f"callgraph_c/{queryFile}",
                "query_params": {"foo": "bar"},
            }
        )
        res = {}
        for r in qry:
            s = r["src_loc"] if not reverse else r["dst_loc"]
            d = r["dst_loc"] if not reverse else r["src_loc"]
            c = r["call_loc"]
            diff = self._directoryDifference(s, d)
            if s not in res:
                res[s] = []
            res[s].append(
                {
                    "id": d,
                    "call_location": c,
                    "function_name": r["dst_name"],
                    "direct": True,
                    "argCount": True,
                    "argMatch": True,
                    "globalAccess": False,
                    "sameFile": diff == 0,
                    "dircDiff": diff,
                    "enclosingVar": "",
                }
            )
        if self.USE_CACHE:
            with open(f"{CACHE_DIR}/cache_{queryFile}_{reverse}.json", "w") as f:
                json.dump(res, f)
        return res

    def _parseExprCalls(self, queryFile="exprCalls.ql", includeParam=False):
        if os.path.exists(f"{CACHE_DIR}/cache_{queryFile}.json") and self.USE_CACHE:
            with open(f"{CACHE_DIR}/cache_{queryFile}.json") as f:
                return json.load(f)
        res = client.query(
            {
                "cp_name": self.DB_NAME,
                "project_id": self.PROJ_ID,
                "query_tmpl": f"callgraph_c/{queryFile}",
                "query_params": {"foo": "bar"},
            }
        )
        parsed = {}
        for r in res:
            if r["cid"] not in parsed:
                parsed[r["cid"]] = {**r, "argIdx": -1, "arg": [r["arg"]]}
                continue
            parsed[r["cid"]]["arg"].append(r["arg"])

        parsed = [parsed[k] for k in parsed.keys()]

        num_comp = len(parsed) * len(self.fptrac.keys())

        print("Number of comps to run", num_comp)

        if num_comp > 20000000:
            # Give up, too many
            if artiphishell_should_fail_on_error():
                assert False, "Giving up ptr call matching, est num comp"
            else:
                parsed = parsed[:5000]
                self.fptrac = dict(list(self.fptrac.items())[:5000])

        possible_calls = {}
        for call in parsed:
            for fk in self.fptrac.keys():
                func = self.fptrac[fk]
                argCount = len(call["arg"]) == len(func["param"])
                argMatch = [a.replace("const", "").strip() for a in call["arg"]] == [
                    a.replace("const", "").strip() for a in func["param"]
                ]
                if not argMatch:
                    continue
                dircDiff = abs(len(call["id"].split("/")) - len(fk.split("/"))) + len(
                    [
                        1
                        for a, b in zip(
                            call["id"].split(":")[1].split("/"),
                            fk.split(":")[1].split("/"),
                        )
                        if a != b
                    ]
                )

                dircDiff = self._directoryDifference(call["id"], fk)
                if call["id"] not in possible_calls:
                    possible_calls[call["id"]] = []
                possible_calls[call["id"]].append(
                    {
                        "id": fk,
                        "call_location": call["cid"],
                        "function_name": func["name"],
                        "direct": False,
                        "argCount": argCount,
                        "argMatch": argMatch,
                        "globalAccess": func["isGlobal"] == "true",
                        "sameFile": dircDiff == 0,
                        "dircDiff": dircDiff,
                        "enclosingVar": func["enclosingVar"],
                    }
                )

        # Inverse graph
        possible_calls_r = {}
        for k in possible_calls.keys():
            for v in possible_calls[k]:
                if v["id"] not in possible_calls_r:
                    possible_calls_r[v["id"]] = []
                possible_calls_r[v["id"]].append({**v, "id": k})

        res = [possible_calls, possible_calls_r]
        if self.USE_CACHE:
            with open(f"{CACHE_DIR}/cache_{queryFile}.json", "w") as f:
                json.dump(res, f)
        return res

    def get_func_by_id(self, id):
        return self.allfun.get(id)

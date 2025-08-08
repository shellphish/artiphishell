import os
from neo4j import GraphDatabase
from urllib.parse import urlparse
from callgraph_c import BetterCallGraph
from callgraph_java import JavaCallGraph
from ptr_relation import FunctionPointerRelation, GlobalVariableRelation
from shellphish_crs_utils.models.symbols import SourceLocation
from analysis_graph.models.cfg import CFGFunction, CFGGlobalVariable
from analysis_graph.api.register_call import (
    register_call_relationship,
)
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from collections import namedtuple
import asyncio
from pathlib import Path
from neo4j import GraphDatabase

import logging

logging.basicConfig()

_l = logging.getLogger(__name__)

CP_NAME = os.environ.get("CP_NAME")
PROJ_ID = os.environ.get("PROJ_ID")
VERBOSE = os.environ.get("VERBOSE", "false").lower() == "true"
LANG = os.environ.get("LANG", "null")


function_index_path=os.getenv("FUNCTION_INDEX_PATH")
function_json_dir_path=os.getenv("FUNCTION_JSON_DIR")
try:
    resolver=LocalFunctionResolver(function_index_path, function_json_dir_path)
except Exception as e: 
    _l.warning(f"Failed to initialize LocalFunctionResolver: {e}")
    _l.warning("Falling back to RemoteFunctionResolver")
    resolver = RemoteFunctionResolver(cp_name=CP_NAME, project_id=PROJ_ID)
    
def parse_codeql_location(location: str) -> tuple:
    "Parse the location string from codeql report"
    location = location[7:]
    location_split = location.split(":")
    filepath = location_split[0]
    startline = int(location_split[1])
    startoffset = int(location_split[2])
    endline = int(location_split[3])
    endoffset = int(location_split[4])
    location_info = namedtuple(
        "Location", ["filepath", "startline", "startoffset", "endline", "endoffset"]
    )
    return location_info(filepath, startline, startoffset, endline, endoffset)


total_calls = 0
registed_calls = 0


def get_neo4j_driver():
    bolt_url_with_auth = os.environ.get("ANALYSIS_GRAPH_BOLT_URL", None)
    if os.getenv('CRS_TASK_NUM'):
        bolt_url_with_auth = bolt_url_with_auth.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
    else:
        if 'TASKNUM' in bolt_url_with_auth:
            raise ValueError("Env CRS_TASK_NUM is not set but ANALYSIS_GRAPH_BOLT_URL contains TASKNUM")
    if bolt_url_with_auth is None:
        raise ValueError("BOLT URL not set")
    # Parse the URL to extract credentials
    parsed_url = urlparse(bolt_url_with_auth)

    # Extract username and password
    auth_part = parsed_url.netloc.split('@')[0]
    username, password = auth_part.split(':')

    # Extract host and port
    host_part = parsed_url.netloc.split('@')[1]

    # Reconstruct the URL without auth
    bolt_url = f"{parsed_url.scheme}://{host_part}"

    driver = GraphDatabase.driver(bolt_url, auth=(username, password))
    return driver

def get_identifier_from_funciton_resolver(name, filepath, line, resolver):
    file_indices = set(resolver.find_by_filename(filepath))
    if not file_indices:
        # _l.warning(f"No file indices found for {filepath}")
        return None
    func_indices = set(resolver.find_by_funcname(name))
    if not func_indices:
        # _l.warning(f"No function indices found for {name}")
        return None
    intersection = file_indices.intersection(func_indices)
    if len(intersection) == 1:
        return intersection.pop()
    elif len(intersection) > 1:
        location = SourceLocation(
            full_file_path=Path(filepath),
            file_name=Path(filepath).name,
            line_number=int(line),
            function_name=name,
        )
        return resolver.resolve_source_location(location)[0][0]
    else:
        # _l.warning(f"No intersection found for {name} in {filepath} at line {line}")
        return None

def register_one(cg, caller_id, callee_id, call, callType, handleGV=True):
    global registed_calls
    registed_calls += 1
    _l.debug(
        f"{registed_calls}/{total_calls} {registed_calls / (total_calls + 1):.2%} "
    )
    try:
        caller = cg.get_func_by_id(caller_id)
        callee = cg.get_func_by_id(callee_id)
        if not callee:
            _l.warning(f"Callee {callee_id} not found")
            return
        if not caller:
            _l.warning(f"Caller {caller_id} not found")
            return
        register_call_relationship(
            caller_function_name=caller["name"],
            caller_file_name=parse_codeql_location(caller["loc"]).filepath,
            callee_function_name=callee["name"],
            callee_file_name=parse_codeql_location(callee["loc"]).filepath,
            call_type=callType,
            solver=resolver,
            # properties=call
        )
        # Handle GV:
        if (
            handleGV
            and "globalAccess" in call
            and call["globalAccess"]
            and call["enclosingVar"] != ""
            and False  # Just don't...
        ):
            dst_id = get_identifier_from_funciton_resolver(
                callee["name"],
                parse_codeql_location(callee["loc"]).filepath,
                parse_codeql_location(callee["loc"]).startline,
                resolver,
            )
            var = CFGGlobalVariable.get_or_create({"identifier": call["enclosingVar"]})[
                0
            ]
            dst = CFGFunction.get_or_create({"identifier": dst_id})[0]
            if not var.takes_pointer_of_function.is_connected(dst):
                var.takes_pointer_of_function.connect(dst)
    except ValueError as e:
        _l.warning(e)
    except Exception as e:
        _l.warning(e)
        if artiphishell_should_fail_on_error():
            raise

def batch_create_relationships(driver, relationships, batch_size=5000):
    """
    Accelerate the creation of relatinships in neo4j
    """
    def create_batch(tx, batch):
        query = """
        UNWIND $batch AS rel
        MATCH (src:CFGFunction {identifier: rel.src}), (dst:CFGFunction {identifier: rel.dst})
        CREATE (src)-[r:DIRECTLY_CALLS]->(dst)
        """
        tx.run(query, batch=batch)
    
    with driver.session() as session:
        total_batches = len(relationships) // batch_size + (1 if len(relationships) % batch_size > 0 else 0)
        for i in range(total_batches-1):
            batch = relationships[i * batch_size : (i + 1) * batch_size]
            session.execute_write(create_batch, batch=batch)
            _l.info(f"Processed batch {i // batch_size + 1}/{total_batches} with {len(batch)} relationships")
        bach = relationships[(total_batches - 1) * batch_size :]
        if bach:
            session.execute_write(create_batch, batch=bach)
            _l.info(f"Processed last batch {total_batches} with {len(bach)} relationships")
        

def register_batch(args):
    for arg in args:
        cg, caller_id, callee_id, call, callType = arg
        register_one(cg, caller_id, callee_id, call, callType)
    _l.info("Runner finished")


async def main(cg: BetterCallGraph | JavaCallGraph):
    loop = asyncio.get_running_loop()
    callees = cg.get_all_callees()
    global total_calls
    total_calls = sum([len(calls) for calls in callees.values()])
    tasks = []
    relationships = []
    if isinstance(cg, JavaCallGraph):
        for caller_id in callees.keys():
            if "identifier" not in cg.allfun[caller_id]:
                continue
            caller_resolver_id = cg.allfun[caller_id]["identifier"]
            calls = callees[caller_id]
            for call in calls:
                callee_id = call["id"]
                if "identifier" not in cg.allfun[callee_id]:
                    continue
                callee_resolver_id = cg.allfun[callee_id]["identifier"]
                relationships.append({
                    "src": caller_resolver_id,
                    "dst": callee_resolver_id,
                })
        bolt_url_with_auth = os.environ.get("ANALYSIS_GRAPH_BOLT_URL", None)
        if os.getenv('CRS_TASK_NUM'):
            bolt_url_with_auth = bolt_url_with_auth.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
        else:
            if 'TASKNUM' in bolt_url_with_auth:
                raise ValueError("Env CRS_TASK_NUM is not set but ANALYSIS_GRAPH_BOLT_URL contains TASKNUM")
        if bolt_url_with_auth is None:
            raise ValueError("BOLT URL not set")
        # Parse the URL to extract credentials
        parsed_url = urlparse(bolt_url_with_auth)

        # Extract username and password
        auth_part = parsed_url.netloc.split('@')[0]
        username, password = auth_part.split(':')

        # Extract host and port
        host_part = parsed_url.netloc.split('@')[1]

        # Reconstruct the URL without auth
        bolt_url = f"{parsed_url.scheme}://{host_part}"

        driver = GraphDatabase.driver(bolt_url, auth=(username, password))
        batch_create_relationships(driver, relationships)
        return
    task_per_runner = 50
    for caller_id in callees.keys():
        calls = callees[caller_id]
        for call in calls:
            callee_id = call["id"]
            direct = call["direct"] if "direct" in call else not call["reflected"]
            callType = "direct_call" if direct else "may_indirect_call"
            tasks.append([cg, caller_id, callee_id, call, callType])
            if len(tasks) >= 1000:
                print(
                    f"Das ist ein befehl - {len(tasks)} tasks with {task_per_runner} per runner", flush=True
                )
                runners = [
                    loop.run_in_executor(
                        None, register_batch, tasks[i : i + task_per_runner]
                    )
                    for i in range(0, len(tasks), task_per_runner)
                ]
                _l.info(f"{len(runners)} runners in progress")
                await asyncio.gather(*runners)
                tasks = []
    if tasks:
        _l.info(f"LEFTOVER TASKS {len(tasks)}")
        register_batch(tasks)
        _l.info("ALL TASKS DISPATCHED")


def funcptrs_in_funcs(cg: BetterCallGraph):
    rel = FunctionPointerRelation(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
    funcs = rel.query("enclosingFunc")
    print("Query returned", len(funcs), "function pointers in functions")
    for f in funcs:
        accessor = f["URL for v"]
        accessee = f["URL for dst"]
        register_one(cg, accessor, accessee, {}, "takes_pointer_of_function", False)


def funcptrs_in_globals(cg: BetterCallGraph):
    rel = FunctionPointerRelation(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
    funcs = rel.query("enclosingGVar")
    print("Query returned", len(funcs), "function pointers in globals")
    for f in funcs:
        try:
            accessor = f["URL for v"]  # GlobalVariable
            accessee = f["URL for dst"]  # Function
            caller = accessor  # No way to get ID
            callee = cg.get_func_by_id(accessee)
            if not callee:
                _l.warning(f"Callee {accessee} not found")
                continue
            callee = get_identifier_from_funciton_resolver(
                callee["name"], parse_codeql_location(callee["loc"]).filepath, 
                parse_codeql_location(callee["loc"]).startline,
                resolver
            )
            if ("/harness/" in accessee) ^ ("/harness/" in callee):
                print("\x1b[33m>>>>>>>>>>>>>>>>THIS IS HORRIBLE>>>>>>>>>>>>>>>>\x1b[0m\n"*10)
                print("accessee",accessee)
                print("callee",callee)
                print("cg.get_func_by_id(accessee)",cg.get_func_by_id(accessee))
                print("\x1b[33m>>>>>>>>>>>>>>>>THIS IS HORRIBLE>>>>>>>>>>>>>>>>\x1b[0m\n"*10)
                exit(114)
            var = CFGGlobalVariable.get_or_create({"identifier": caller})[0]
            dst = CFGFunction.get_or_create({"identifier": callee})[0]
            if not var.takes_pointer_of_function.is_connected(dst):
                var.takes_pointer_of_function.connect(dst, {"ref": f["URL for fa"]})
        except Exception as e:
            _l.warning(f"Error processing function pointer in globals: {e}")

def globals_in_globals():
    rel = GlobalVariableRelation(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
    globals = rel.query("enclosingGVar")
    print("Query returned", len(globals), "global pointers in globals")
    for g in globals:
        try:
            accessor = g["URL for v"]  # GlobalVariable
            accessee = g["URL for dst"]  # GlobalVariable
            caller = accessor  # No way to get ID
            callee = accessee  # No way to get ID
            var1 = CFGGlobalVariable.get_or_create({"identifier": caller})[0]
            var2 = CFGGlobalVariable.get_or_create({"identifier": callee})[0]
            if not var1.takes_pointer_of_global.is_connected(var2):
                var1.takes_pointer_of_global.connect(var2, {"ref": g["URL for va"]})
        except Exception as e:
            _l.warning(f"Error processing function pointer in globals: {e}")

def globals_in_funcs(cg):
    rel = GlobalVariableRelation(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
    globals = rel.query("enclosingFunc")
    print("Query returned", len(globals), "global var access in functions")
    for g in globals:
        try:
            accessor = g["URL for v"]  # Function
            accessee = g["URL for dst"] # GlobalVariable
            caller = cg.get_func_by_id(accessor)
            if not caller:
                _l.warning(f"Caller {accessor} not found")
                continue
            caller = get_identifier_from_funciton_resolver(
                caller["name"], parse_codeql_location(caller["loc"]).filepath, 
                parse_codeql_location(caller["loc"]).startline,
                resolver
            )
            callee = accessee
            var = CFGGlobalVariable.get_or_create({"identifier": callee})[0]
            func = CFGFunction.get_or_create({"identifier": caller})[0]
            if not func.takes_pointer_of_global.is_connected(var):
                func.takes_pointer_of_global.connect(var, {"ref": g["URL for va"]})
        except Exception as e:
            _l.warning(f"Error processing function pointer in globals: {e}")


def allfunctions(cg: BetterCallGraph | JavaCallGraph):
    funcs = cg.allfun
    count = 0
    print("Query returned", len(funcs), "functions")
    import time
    t0 = time.time()
    
    # Process in batches
    BATCH_SIZE = 500  # Experiment with 100-1000
    batch_data = []
    # get_all_keys(resolver)
    for id, prop in funcs.items():
        try:
            count += 1
            loc = parse_codeql_location(id)
            identifier = get_identifier_from_funciton_resolver(
                prop["name"], loc.filepath, loc.startline, resolver
            )
            
            if not identifier:
                # _l.warning(f"!!--!!--!!Identifier for function {prop['name']} not found")
                continue
                
            batch_data.append((id, identifier, prop))
            
            # Process batch when full
            if len(batch_data) >= BATCH_SIZE:
                process_batch(cg, batch_data)
                batch_data = []
            
            if count % 10 == 0:
                t1 = time.time()
                print(f"Processed {count} functions in {t1 - t0:.2f} seconds")
                
        except Exception as e:
            continue
    
    # Process remaining batch
    if batch_data:
        process_batch(cg, batch_data)


def process_batch(cg, batch_data):
    """Process entire batch in single Cypher query"""
    neo4j_driver = get_neo4j_driver()
    with neo4j_driver.session() as session:
        # Prepare batch data for UNWIND
        cypher_data = [
            {"id": id, "identifier": identifier} 
            for id, identifier, prop in batch_data
        ]
        
        query = """
        UNWIND $batch_data AS row
        MERGE (f:CFGFunction {identifier: row.identifier})
        RETURN row.id, row.identifier, f
        """
        try:
            result = session.run(query, batch_data=cypher_data)
        except Exception as e:
            _l.error(f"Error processing batch: {e}")
            result = []
        # Update in-memory structure
        for record in result:
            cg.allfun[record["row.id"]]["identifier"] = record["row.identifier"]

if __name__ == "__main__":
    assert LANG in ["c", "c++", "jvm", "java"], f"Unsupported language: {LANG}"
    is_c = LANG in ["c", "c++"]
    cg = (
        BetterCallGraph(project_id=PROJ_ID, db_name=CP_NAME, use_cache=True)
        if is_c
        else JavaCallGraph(project_id=PROJ_ID, db_name=CP_NAME, use_cache=False)
    )
    # allfunctions_with_periodic_cache_clear(cg)
    allfunctions(cg)
    asyncio.run(main(cg))
    if is_c:
        print("==" * 20, "Processing function pointers in C/C++" )
        funcptrs_in_funcs(cg)
        print("==" * 20, "Processing function pointers in globals" )
        funcptrs_in_globals(cg)
        print("==" * 20, "Processing globals in globals" )
        globals_in_funcs(cg)
        print("==" * 20, "Processing globals in functions" )
        globals_in_globals()
    print("==" * 20)
    print("PYTHON exiting (analysis graphql v2.0)")
    print("==" * 20)
    # import time
    # time.sleep(114514)


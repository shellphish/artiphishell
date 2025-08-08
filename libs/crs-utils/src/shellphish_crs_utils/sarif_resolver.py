import logging
import sarif.loader as sarif_loader


from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from shellphish_crs_utils.models.indexer import FunctionIndex, FUNCTION_INDEX_KEY
from shellphish_crs_utils.function_resolver import LocalFunctionResolver, RemoteFunctionResolver
from shellphish_crs_utils.models.symbols import SourceLocation

from pathlib import Path
from typing import List, Dict, Any, Optional, Union

logger = logging.getLogger("sarif_resolver")
logger.setLevel(logging.DEBUG)

'''
==============================================================================================================================================
A FEW ASSUMPTIONS/NOTES
==============================================================================================================================================

# NOTE: For the AIxCC game, there is gonna be one and only one result entry per sarif
# NOTE: The locations that are included in the results.location can be considered as sinks.
#       (the function where the vuln should be triggered)
# NOTE: For our purposes, I think it is safe to assume there exists only ONE entry in the locations dict (our sink).
#       Check "The locations array SHALL NOT be used to specify distinct occurrences of the same result which can be corrected independently."
#       In https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127698.
# NOTE: The locations mentioned in the reports are only considered valid if they are referencing the focused repo.
        DARPA wants us to look for vulnerability there, thus any other location is basically out of scope.
==============================================================================================================================================
'''

class InvalidSarifReport(Exception):
    """
    Exception raised when the SARIF report is invalid.
    """

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

class SarifLocation:
    '''Represents a SARIF result entry.
    required fields: keyindex, file, func, line
    optional fields: None
    '''
    def __init__(self, keyindex, file:str, func:str, line:int, region: dict):

        self.keyindex = keyindex
        self.file = file
        self.func = func
        self.line = line
        self.region = region

    def __repr__(self):
        return f"SarifLocation(keyindex={self.keyindex}, file={self.file}, func={self.func}, line={self.line})"

class SarifCodeFlow:
    '''Represents a SARIF code flow entry.
    required fields: code_flow_id, locations
    optional fields: None
    '''
    def __init__(self, code_flow_id):
        self.code_flow_id = code_flow_id
        self.locations: List[SarifLocation] = []

    def __repr__(self):
        return f"SarifCodeFlow(code_flow_id={self.code_flow_id}, locations={self.locations})"

class SarifRule:
    '''
    Represents a SARIF rule entry.
    '''
    def __init__(self, rule_id: str, short_description: str = '', long_description: str = '', description: str = '', severity: str = '', security_severity: str = '', tags: List[str] = []):
        self.rule_id = rule_id
        # This is holding all the short, long and descriptions (they can be different)
        self.short_description: str = short_description
        self.long_description:str = long_description
        self.description:str = description
        # Extra fields: severity, security-severity, tags
        self.severity:str = severity
        self.security_severity: str = security_severity
        self.tags: List[str] = tags

    def __repr__(self):
        return f"SarifRule(rule_id={self.rule_id}, short_description={self.short_description}, long_description={self.long_description}, description={self.description}, severity={self.severity}, security_severity={self.security_severity}, tags={self.tags})"

class SarifResult:
    '''Represents a SARIF result entry.
    required fields: rule_id, locations
    optional fields: message, codeflows
    '''
    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        self.message = ''
        self.sarif_rule: SarifRule = None
        self.locations: List[SarifLocation] = []
        self.codeflows: List[SarifCodeFlow] = []
        self.related_locations: List[SarifLocation] = []

    def __repr__(self):
        return f"SarifResult(rule_id={self.rule_id}, rule={self.sarif_rule}, message={self.message}, locations={self.locations}, codeflows={self.codeflows}, related_locations={self.related_locations})"


class SarifResolver:

    def __init__(self, sarif_path: Union[str, Path],
                       func_resolver: Union[LocalFunctionResolver, RemoteFunctionResolver]):

        # To resolve the location in the Sarif report
        self.func_resolver = func_resolver

        # Path where the sarif report is
        self.sarif_path = Path(sarif_path) if type(sarif_path) == str else sarif_path

        # Load the sarif file
        try:
            self.sarif = sarif_loader.load_sarif_file(self.sarif_path)
            self.valid_sarif = True
        except Exception as e:
            logger.warning(f'  🚮 Invalid SARIF report {self.sarif_path}: {e}')
            self.valid_sarif = False

        self.got_results = False
        # Caching the results once we have processed them
        self.sarif_results = []

        # Caching the dumb results once we have processed them
        # (results for which we could not resolve the location, e.g., shell.c.in for sqlite3)
        self.dumb_sarif_results = []

        self.rules_metadata = {}

    def is_valid(self) -> bool:
        """
        Check if the sarif report is valid.
        """
        return self.valid_sarif

    def collect_rules_metadata(self) -> Dict[str, SarifRule]:
        if not self.is_valid():
            raise InvalidSarifReport("Invalid SARIF report")

        for run in self.sarif.data['runs']:
            rules = run.get('tool', {}).get('driver', {}).get('rules', [])
            for rule in rules:
                rule_id = rule['id']
                short_description = rule.get('shortDescription', {}).get('text', '')
                long_description = rule.get('longDescription', {}).get('text', '')
                description = rule.get('fullDescription', {}).get('text', '')
                severity = rule.get('properties', {}).get('problem.severity', '')
                security_severity = rule.get('properties', {}).get('security-severity', '')
                tags = rule.get('properties', {}).get('tags', [])
                self.rules_metadata[rule_id] = SarifRule(rule_id, short_description, long_description, description, severity, security_severity, tags)

    def get_single_rule_metadata(self, rule_id:str) -> Optional[SarifRule]:
        if not self.rules_metadata:
            self.collect_rules_metadata()

        return self.rules_metadata.get(rule_id, None)

    def get_dumb_results(self):
        # NOTE: the dumb results are computed when we compute the normal results
        if not self.is_valid():
            raise InvalidSarifReport("Invalid SARIF report")

        if self.got_results:
            return self.dumb_sarif_results
        else:
            _ = self.get_results()

        return self.dumb_sarif_results

    def get_results(self):

        if not self.is_valid():
            raise InvalidSarifReport("Invalid SARIF report")

        logger.info(f"🔍 Resolving SARIF report {self.sarif_path}...")

        if self.got_results:
            # Just return the cached results
            return self.sarif_results
        else:
            # Signal that we processed the results
            self.got_results = True

        for result in self.sarif.get_results():
            sarif_result = SarifResult(result['ruleId'])
            dumb_sarif_result = DumbSarifResult(result['ruleId'])

            sarif_rule:SarifRule = self.get_single_rule_metadata(result['ruleId'])

            if sarif_rule == None:
                logger.debug(f"  🚮 Warning has no rule metadata for {result['ruleId']}, skipping.")
                continue

            sarif_result.sarif_rule = sarif_rule
            dumb_sarif_result.sarif_rule = sarif_rule

            # SARIF MAY contain a message
            if 'message' in result:
                message = result['message'].get('text', '')
                sarif_result.message = message
                dumb_sarif_result.message = message

            ############################################
            # 📍 Extract locations
            ############################################
            locs = result.get('locations', [])
            if len(locs) != 0:
                for location in locs:
                    loc_file = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                    if not loc_file:
                        continue
                    region = location.get('physicalLocation', {}).get('region', {})
                    loc_line = region.get('startLine')

                    # If we have file and line, let's lookup the function
                    # Translate the loc_file with the function resolver
                    if loc_file and loc_line:
                        all_funcs_in_file:List[FUNCTION_INDEX_KEY] = list(self.func_resolver.find_by_filename(loc_file))

                        if not all_funcs_in_file:
                            # Let's save a dumb sarif location and move on
                            logger.info(f"  🤪 Warning has no function associated to {loc_file}. Saving DumbSarifResult!")
                            sarif_dumb_loc = DumbSarifLocation(
                                file=loc_file,
                                line=loc_line
                            )
                            dumb_sarif_result.locations.append(sarif_dumb_loc)
                            continue

                        loc_func:FunctionIndex = None
                        for func_in_file in all_funcs_in_file:
                            func_start, func_end = self.func_resolver.get_function_boundary(func_in_file)

                            if loc_line >= func_start and loc_line <= func_end:
                                loc_func:FunctionIndex = func_in_file

                                function_info:FunctionIndex = self.func_resolver.get(func_in_file)

                                # NOTE: for now, we consider ONLY the locations in the focus repo.
                                if function_info.focus_repo_relative_path:
                                    sarif_loc = SarifLocation(
                                        keyindex=func_in_file,
                                        file=function_info.focus_repo_relative_path,
                                        func=function_info.funcname,
                                        line=loc_line,
                                        region=region
                                    )
                                    # Add detailed information about the location
                                    sarif_result.locations.append(sarif_loc)

                                    # NOTE: we found a matching location in the focused repo, stop here.
                                    break
                                else:
                                    # NOTE: this location is not in the focused repo, skip it for now.
                                    continue

                        # NOTE: if we are here, we could not find a way to resolve this location...
                        if not loc_func:
                            logger.debug(f"  🚮 Warning has no function associated to {loc_file} at line {loc_line}, skipping.")
                            continue
                    else:
                        # NOTE: we only have a file loc, not line, skip.
                        # TODO
                        continue
            else:
                logger.debug("  🚮 Warning has no location, skipping.")
                continue

            ############################################
            # 🔀 Extract code flows
            ############################################
            code_flows = result.get('codeFlows', [])
            if len(code_flows) == 0:
                logger.debug("  🚮 Warning has no code flows, skipping.")
            else:
                logger.debug(f" 🔀 Found {len(code_flows)} code flows associated to warning {result['ruleId']}.")

                # Let's collect all the threadFlows
                for code_flow_id, thread_flow in enumerate(code_flows):
                    sarif_code_flow = SarifCodeFlow(code_flow_id)
                    # NOTE: inspecting all the thread flows in the code flow
                    locations = thread_flow.get('threadFlows', [])[0].get('locations', [])

                    # Extract all the locations first
                    for thread_loc in locations:
                        thread_loc_file = thread_loc['location'].get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                        thread_loc_region = thread_loc['location'].get('physicalLocation', {}).get('region', {})
                        thread_loc_line = thread_loc_region.get('startLine')
                        thread_loc_msg = thread_loc['location'].get('message', {}).get('text') or ''

                        # Here we are a bit more strict, we want a codeflow to be precise.
                        if not thread_loc_file or not thread_loc_line:
                            logger.debug("  🚮 Warning has no thread flow location, skipping.")
                            continue
                        all_funcs_in_file = list(self.func_resolver.find_by_filename(thread_loc_file))

                        if not all_funcs_in_file:
                            logger.debug(f"  🚮 Warning has no function associated to {thread_loc_file}, skipping.")
                            continue

                        loc_func:FunctionIndex = None
                        for func_in_file in all_funcs_in_file:
                            func_start, func_end = self.func_resolver.get_function_boundary(func_in_file)

                            if thread_loc_line >= func_start and thread_loc_line <= func_end:
                                loc_func:FunctionIndex = func_in_file

                                function_info:FunctionIndex = self.func_resolver.get(func_in_file)

                                # NOTE: for now, we consider ONLY the locations in the focus repo.
                                if function_info.focus_repo_relative_path:
                                    sarif_loc = SarifLocation(
                                        keyindex=func_in_file,
                                        file=function_info.focus_repo_relative_path,
                                        func=function_info.funcname,
                                        line=thread_loc_line,
                                        region=thread_loc_region
                                    )
                                    # Add detailed information about the location
                                    sarif_code_flow.locations.append(sarif_loc)

                                    # NOTE: we found a matching location in the focused repo, stop here.
                                    break
                                else:
                                    # NOTE: this location is not in the focused repo, skip it for now.
                                    continue

                        # NOTE: if we are here, we could not find a way to resolve this location...
                        if not loc_func:
                            logger.debug(f"  🚮 Warning has no function associated to {thread_loc_file} at line {thread_loc_line}, skipping.")
                            continue

                    # Finish unpacking this code flow entry
                    if len(sarif_code_flow.locations) > 0:
                        sarif_result.codeflows.append(sarif_code_flow)
                    else:
                        logger.debug("  🚮 Warning has no code flow locations, skipping.")
                        continue

            ############################################
            # 🔀 Extract related locations
            ############################################
            related_locations = result.get('relatedLocations', [])
            if len(related_locations) == 0:
                logger.debug("  🚮 Warning has no related locations, skipping.")
            else:
                logger.debug(f" 🔀 Found {len(related_locations)} related locations associated to warning {result['ruleId']}.")
                for related_location in related_locations:
                    # Extract basic information from the related location
                    # related_id = related_location.get('id', 0)
                    rel_loc_file = related_location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                    if not rel_loc_file:
                        logger.debug("  🚮 Warning has no file associated to related location, skipping.")
                        continue

                    rel_loc_region = related_location.get('physicalLocation', {}).get('region', {})
                    rel_loc_line = rel_loc_region.get('startLine')
                    # rel_loc_msg = related_location.get('message', {}).get('text', '')

                    if not rel_loc_line:
                        logger.debug("  🚮 Warning has no line associated to related location, skipping.")
                        continue

                    # Use resolve_with_leniency to find the function
                    try:
                        func_key = next(self.func_resolver.resolve_with_leniency(f"{rel_loc_file}:{rel_loc_line}"))
                    except (ValueError, StopIteration, KeyError) as e:
                        logger.debug(f"  🚮 resolve_with_leniency failed for {rel_loc_file} at line {rel_loc_line}: {e}")
                        func_key = None

                    if func_key:
                        function_info = self.func_resolver.get(func_key)

                        # NOTE: for now, we consider ONLY the locations in the focus repo.
                        if function_info.focus_repo_relative_path:
                            sarif_rel_loc = SarifLocation(
                                keyindex=func_key,
                                file=function_info.focus_repo_relative_path,
                                func=function_info.funcname,
                                line=rel_loc_line,
                                region=rel_loc_region
                            )
                            sarif_result.related_locations.append(sarif_rel_loc)
                        else:
                            # NOTE: this location is not in the focused repo, skip it for now.
                            logger.debug(f"  🚮 Warning function is not in focus repo for {rel_loc_file} at line {rel_loc_line}, skipping.")
                    else:
                        # Let's save a dumb sarif location and move on
                        logger.info(f"  🤪 Warning has no function associated to {rel_loc_file} in line {rel_loc_line}. Saving DumbSarifResult!")
                        dumb_sarif_result.related_locations.append(DumbSarifLocation(
                            file=rel_loc_file,
                            line=rel_loc_line
                        ))

            # We are adding here only the results that have resolved locations!
            if len(sarif_result.locations) > 0:
                self.sarif_results.append(sarif_result)

            # Add dumb results if they have any locations, codeflows, or related_locations
            if (len(dumb_sarif_result.locations) > 0 or
                len(dumb_sarif_result.related_locations) > 0):
                self.dumb_sarif_results.append(dumb_sarif_result)

        return self.sarif_results

    def get_rules_metadata(self) -> Dict[str, SarifRule]:
        if not self.rules_metadata:
            self.collect_rules_metadata()
        return self.rules_metadata

# ***********************************************************************************************
# ***********************************************************************************************
# ********* THE ONLY COMPONENT ALLOWED TO USE THE FOLLOWING CLASSES IS THE DUMB SARIF GUY *******
# ************************* EVERYONE ELSE SHOULD USE THE SARIF RESOLVER *************************
# ***********************************************************************************************
# ***********************************************************************************************

class DumbSarifLocation:
    def __init__(self, file:str, line:int):
        self.file = file
        self.line = line

    def __repr__(self):
        return f"DumbSarifLocation(file={self.file}, line={self.line})"

class DumbSarifCodeFlow:
    def __init__(self, code_flow_id):
        self.code_flow_id = code_flow_id
        self.locations: List[DumbSarifLocation] = []

    def __repr__(self):
        return f"DumbSarifCodeFlow(code_flow_id={self.code_flow_id}, locations={self.locations})"

class DumbSarifResult:
    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        self.message = ''
        self.sarif_rule: SarifRule = None
        self.locations: List[DumbSarifLocation] = []
        self.codeflows: List[DumbSarifCodeFlow] = []
        self.related_locations: List[DumbSarifLocation] = []

    def __repr__(self):
        return f"DumbSarifResult(rule_id={self.rule_id}, message={self.message}, locations={self.locations}, codeflows={self.codeflows}, related_locations={self.related_locations})"


class DumbSarifResolver:
    """
    A dumb sarif resolver that does not resolve the locations.
    """

    def __init__(self, sarif_path: Union[str, Path], oss_fuzz_project: OSSFuzzProject):
        # Path where the sarif report is
        self.sarif_path = Path(sarif_path) if type(sarif_path) == str else sarif_path

        # Load the sarif file
        try:
            self.sarif = sarif_loader.load_sarif_file(self.sarif_path)
            self.valid_sarif = True
        except Exception as e:
            self.valid_sarif = False

        # Caching the results once we have processed them
        self.sarif_results = []

        # The ***UNBUILT*** OSS Fuzz Project
        self.cp = oss_fuzz_project

    def is_valid(self) -> bool:
        """
        Check if the sarif report is valid.
        """
        return self.valid_sarif

    def find_by_filename(self, filename: str) -> str:
        """
        If we can resolve the filename manually, we try to
        return the focused repo relative path, otherwise
        we return None.
        """
        if not self.is_valid():
            raise InvalidSarifReport("Invalid SARIF report")

        found_paths = []
        for path in Path(self.cp.project_source).rglob(filename):
            if path.is_file():
                found_path = path.relative_to(self.cp.project_source)
                found_paths.append(found_path)

        # NOTE: since we have no way to understand what is a good path, we just return the first one. YOLO!
        if len(found_paths) == 0:
            return None
        else:
            return found_paths[0]


    def get_results(self):

        if not self.is_valid():
            raise InvalidSarifReport("Invalid SARIF report")

        logger.info(f"🔍 Resolving SARIF report {self.sarif_path}...")

        if len(self.sarif_results) != 0:
            return self.sarif_results

        for result in self.sarif.get_results():
            sarif_result = SarifResult(result['ruleId'])

            # SARIF MAY contain a message
            if 'message' in result:
                message = result['message'].get('text', '')
                sarif_result.message = message

            ############################################
            # 📍 Extract locations
            ############################################
            locs = result.get('locations', [])
            if len(locs) != 0:
                for location in locs:

                    loc_file = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                    if not loc_file:
                        continue

                    loc_line = location.get('physicalLocation', {}).get('region', {}).get('startLine')

                    # If we have file and line, let's lookup the function
                    # Translate the loc_file with the function resolver
                    if loc_file and loc_line:
                        loc_file = self.find_by_filename(loc_file)
                        if loc_file:
                            sarif_result.locations.append(DumbSarifLocation(
                                file=loc_file,
                                line=loc_line
                            ))
            else:
                logger.debug("  🚮 Warning has no location, skipping.")
                continue


            ############################################
            # 🔀 Extract code flow
            # ##########################################
            code_flows = result.get('codeFlows', [])
            if len(code_flows) == 0:
                logger.debug("  🚮 Warning has no code flows, skipping.")
            else:
                logger.debug(f" 🔀 Found {len(code_flows)} code flows associated to warning {result['ruleId']}.")

                # Let's collect all the threadFlows
                for code_flow_id, thread_flow in enumerate(code_flows):
                    sarif_code_flow = DumbSarifCodeFlow(code_flow_id)
                    # NOTE: inspecting all the thread flows in the code flow
                    locations = thread_flow.get('threadFlows', [])[0].get('locations', [])

                    # Extract all the locations first
                    for thread_loc in locations:
                        thread_loc_file = thread_loc['location'].get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                        thread_loc_line = thread_loc['location'].get('physicalLocation', {}).get('region', {}).get('startLine')
                        thread_loc_msg = thread_loc['location'].get('message', {}).get('text') or ''

                        # Here we are a bit more strict, we want a codeflow to be precise.
                        if not thread_loc_file or not thread_loc_line:
                            logger.debug("  🚮 Warning has no thread flow location, skipping.")
                            continue

                        loc_file = self.find_by_filename(thread_loc_file)
                        if loc_file:
                            sarif_code_flow.locations.append(DumbSarifLocation(
                                file=thread_loc_file,
                                line=thread_loc_line
                            ))
                        else:
                            continue

                    # Finish unpacking this code flow entry
                    if len(sarif_code_flow.locations) > 0:
                        sarif_result.codeflows.append(sarif_code_flow)
                    else:
                        logger.debug("  🚮 Warning has no code flow locations, skipping.")
                        continue

            ############################################
            # 🔀 Extract related locations
            ############################################
            related_locations = result.get('relatedLocations', [])
            if len(related_locations) == 0:
                logger.debug("  🚮 Warning has no related locations, skipping.")
            else:
                logger.debug(f" 🔀 Found {len(related_locations)} related locations associated to warning {result['ruleId']}.")
                for related_location in related_locations:
                    rel_loc_file = related_location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
                    if not rel_loc_file:
                        continue

                    rel_loc_line = related_location.get('physicalLocation', {}).get('region', {}).get('startLine')
                    if not rel_loc_line:
                        continue

                    # Translate the rel_loc_file with the find_by_filename method
                    resolved_file = self.find_by_filename(rel_loc_file)
                    if resolved_file:
                        sarif_result.related_locations.append(DumbSarifLocation(
                            file=resolved_file,
                            line=rel_loc_line
                        ))

            # Add the results to the list
            self.sarif_results.append(sarif_result)

        return self.sarif_results

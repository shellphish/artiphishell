import os
import signal
import logging
from pathlib import Path

import yaml
from shellphish_crs_utils.models.crs_reports import KumushiRootCauseReport, KumushiPOICluster, KumushiPOI, KumushiCodeFunction

from kumushi.code_parsing import CodeFunction
from kumushi.data import PoI, PoICluster, PoISource, Program
_l = (logging.getLogger(__name__))
TMP_POI_DIR = Path("/tmp/kumushi_poi")

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type_, value, traceback):
        signal.alarm(0)


def _validate_or_correct_path(p) -> Path | None:
    if isinstance(p, str):
        if not p or p == "None":
            new_p = None
        else:
            new_p = Path(p).absolute()
    else:
        new_p = p

    if new_p is not None:
        if not new_p.exists():
            raise FileNotFoundError(f"Path {new_p} does not exist!")

    return new_p


def absolute_path_finder(src_root: Path, relative_file_path: Path) -> Path | None:
    if os.path.exists(src_root / relative_file_path):
        return src_root / relative_file_path

    poi_src_name = os.path.basename(relative_file_path)
    # attempt resolving by seeing the overlap of the file name
    for dirpath, dirnames, filenames in os.walk(src_root):
        if poi_src_name in filenames:
            poi_src_name_match = os.path.join(dirpath, poi_src_name)
            if not isinstance(relative_file_path, str):
                relative_file_path = str(relative_file_path)
            if poi_src_name_match[-len(relative_file_path) :] == relative_file_path:
                return Path(poi_src_name_match)

    # attempt a hack of finding the start of src and then checking if it exists on the source root
    # find 'src' in the path, and truncate everything before it
    relative_file_path = Path(relative_file_path)
    path_parts = list(relative_file_path.parts)
    if "src" in path_parts:
        src_index = path_parts.index("src")
        new_rel_path = Path("/".join(relative_file_path.parts[src_index:]))
        full_path = src_root / new_rel_path
        if full_path.exists():
            _l.critical(
                f"Found the file by hacking the path: %s! Clang Indexer likely failed earlier!",
                relative_file_path
            )
            return full_path

    return None


def read_src_from_file(src_file, start_line, end_line, backup_code=None):
    src_file = Path(src_file).absolute()
    if start_line is None or end_line is None or not src_file.exists():
        if backup_code is None:
            _l.warning("Attempted to use backup code for a POI, but it is also None!")
        return backup_code

    with open(src_file, "r") as f:
        lines = f.readlines()

    return "".join(lines[start_line - 1:end_line])


class WorkDirContext:
    def __init__(self, path: Path):
        self.path = path
        self.origin = Path(os.getcwd()).absolute()

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.origin)


def convert_poi_to_kumushi_poi(poi: PoI) -> KumushiPOI:
    # Convert CodeFunction to KumushiCodeFunction

    kumushi_function = KumushiCodeFunction.model_validate(poi.function.to_dict())
    # Create KumushiPOI
    return KumushiPOI(
        sources=poi.sources if poi.sources else [PoISource.UNKNOWN],  # You might want to adjust this default
        crash_line_number=poi.crash_line_num,
        crash_line=poi.crash_line,
        code_function=kumushi_function
    )


def convert_poi_clusters_to_kumushi_report(poi_clusters: list[PoICluster], rca_hash: str) -> KumushiRootCauseReport:
    # Convert each PoICluster to KumushiPOICluster
    kumushi_clusters = []

    for cluster in poi_clusters:
        # Convert each PoI in the cluster
        kumushi_pois = [convert_poi_to_kumushi_poi(poi) for poi in cluster.pois]

        # Create KumushiPOICluster
        kumushi_cluster = KumushiPOICluster(
            poi_cluster=kumushi_pois,
            reasoning=cluster.reasoning
        )

        kumushi_clusters.append(kumushi_cluster)

    # Create the final report
    return KumushiRootCauseReport(
        poi_clusters=kumushi_clusters,
        rca_hash=rca_hash,
    )


def convert_kumushi_poi_to_poi(kumushi_poi: KumushiPOI) -> PoI:
    function = CodeFunction(
        kumushi_poi.code_function.name,
        kumushi_poi.code_function.start_line,
        kumushi_poi.code_function.end_line,
        file_path=kumushi_poi.code_function.file_path,
        code=kumushi_poi.code_function.code,
        global_vars=kumushi_poi.code_function.global_vars,
        version=kumushi_poi.code_function.version
    )
    # Create PoI
    return PoI(
        sources=kumushi_poi.sources if kumushi_poi.sources else [PoISource.UNKNOWN],  # You might want to adjust this default
        crash_line_num=kumushi_poi.crash_line_number,
        crash_line=kumushi_poi.crash_line,
        function=function
    )


def convert_kumushi_report_to_poi_clusters(kumushi_report: KumushiRootCauseReport) -> list[PoICluster]:
    poi_clusters = []

    for kumushi_cluster in kumushi_report.poi_clusters:
        pois = [convert_kumushi_poi_to_poi(poi) for poi in kumushi_cluster.poi_cluster]
        poi_clusters.append(PoICluster(pois, reasoning=kumushi_cluster.reasoning))

    return poi_clusters


def save_clusters_to_yaml(poi_clusters: list[PoICluster], output_file: Path, rca_hash: str, program: Program):
    # update pois to be source relative
    new_clusters = []
    for cluster in poi_clusters:
        new_pois = []
        for poi in cluster.pois:
            try:
                poi.function.file_path = poi.function.file_path.relative_to(program.source_root)
            except Exception as e:
                _l.warning("Failed to make the path relative to the source root:", exc_info=True)

            new_pois.append(poi)
        new_clusters.append(PoICluster(new_pois, reasoning=cluster.reasoning, source=cluster.source))

    # Convert to Kumushi format
    kumushi_report = convert_poi_clusters_to_kumushi_report(new_clusters, rca_hash)

    # Convert to dictionary
    report_dict = kumushi_report.model_dump()

    # Save to YAML
    with open(output_file, 'w') as f:
        yaml.safe_dump(report_dict, f, default_flow_style=False, sort_keys=False)


def load_clusters_from_yaml(yaml_path: Path, program: Program) -> list[PoICluster]:
    with open(yaml_path, 'r') as f:
        report_dict = yaml.safe_load(f)

    kumushi_report: KumushiRootCauseReport = KumushiRootCauseReport.model_validate(report_dict)
    poi_clusters = convert_kumushi_report_to_poi_clusters(kumushi_report)

    # update pois to be source relative
    new_clusters = []
    for cluster in poi_clusters:
        new_pois = []
        for poi in cluster.pois:
            poi.function.file_path = program.source_root / poi.function.file_path
            new_pois.append(poi)
        new_clusters.append(PoICluster(new_pois, reasoning=cluster.reasoning, source=cluster.source))

    return new_clusters

def save_clusters_to_file(clusters: list["PoICluster"], file_path: Path) -> None:
    """
    Save a list of PoICluster instances to a file using pickle.

    Args:
        clusters: List of PoICluster objects to save
        file_path: Path where to save the file

    Raises:
        OSError: If there's an issue creating directories or writing to the file
    """
    import pickle

    try:
        # Create parent directories if they don't exist
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Save using pickle (binary mode)
        with open(file_path, "wb") as f:
            pickle.dump(clusters, f, protocol=pickle.HIGHEST_PROTOCOL)
    except OSError as e:
        raise OSError(f"Failed to save list of PoIClusters to {file_path}: {str(e)}")

def load_clusters_from_file(file_path: Path) -> list["PoICluster"]:
    """
    Load a list of PoICluster instances from a pickle file.

    Args:
        file_path: Path to the pickle file

    Returns:
        A list of PoICluster instances

    Raises:
        OSError: If there's an issue reading the file
        pickle.UnpicklingError: If the file contains invalid pickle data
    """
    import pickle

    if not Path(file_path).exists():
        _l.critical("PoI file %s does not exist. Skipping!", file_path)
        return []

    try:
        with open(file_path, "rb") as f:
            clusters = pickle.load(f)
            if not isinstance(clusters, list):
                raise pickle.UnpicklingError(f"Expected a list of PoICluster objects, got {type(clusters)}")
            return clusters
    except OSError as e:
        _l.info(f"Failed to load PoIClusters from {file_path}: {str(e)}")
        return []
    except pickle.UnpicklingError as e:
        raise pickle.UnpicklingError(f"Invalid pickle data in {file_path}: {str(e)}")
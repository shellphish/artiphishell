from collections import defaultdict
import json
import os
from pathlib import Path
import subprocess
import yaml
import logging
from shellphish_crs_utils.pydatatask import PDTRepo
from shellphish_crs_utils.models.target import HarnessInfo, ProjectHarnessMetadata, BuildConfiguration
from shellphish_crs_utils.models.oss_fuzz import ArchitectureEnum, OSSFuzzProjectYAML, SanitizerEnum, AugmentedProjectMetadata
LOG = logging.getLogger("analyze_target")

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


SUPPORTED_ARCHES = [ArchitectureEnum.x86_64]
SUPPORTED_SANITIZERS = [SanitizerEnum.address, SanitizerEnum.undefined, SanitizerEnum.memory, SanitizerEnum.thread]

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--project-id', required=True, type=str)
    parser.add_argument('--include-harness-splitting', action='store_true', default=False)
    parser.add_argument('--metadata-path', required=True, type=Path)
    parser.add_argument('--build-configurations-dir', required=True, type=Path)
    parser.add_argument('--build-configurations-lock-dir', required=True, type=Path)
    parser.add_argument('--harness-infos-dir', required=False, type=Path)
    parser.add_argument('--harness-infos-lock-dir', required=False, type=Path)
    parser.add_argument('--project-harness-metadatas-dir', required=False, type=Path)
    parser.add_argument('--project-harness-metadatas-lock-dir', required=False, type=Path)
    parser.add_argument('--target-split-metadata-path', required=True, type=Path)
    ARGS = parser.parse_args()

    assert ARGS.include_harness_splitting == (ARGS.harness_infos_dir is not None), "Harness info dir should be None if not splitting harnesses and should be set if splitting harnesses"
    assert ARGS.build_configurations_dir is not None, "Build configurations dir should be set"
    assert ARGS.build_configurations_lock_dir is not None, "Build configurations lock dir should be set"

    build_configs_repo = PDTRepo(ARGS.build_configurations_dir, ARGS.build_configurations_lock_dir)
    if ARGS.include_harness_splitting:
        harness_infos_repo = PDTRepo(ARGS.harness_infos_dir, ARGS.harness_infos_lock_dir)
        project_harness_metadatas_dir = PDTRepo(ARGS.project_harness_metadatas_dir, ARGS.project_harness_metadatas_lock_dir)
    else:
        harness_infos_repo = None
        project_harness_metadatas_dir = None

    with open(ARGS.metadata_path, 'r') as f:
        if ARGS.include_harness_splitting:
            # in harness splitting mode, we get the full metadata with the harness info annotated
            meta = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        else:
            meta = OSSFuzzProjectYAML.model_validate(yaml.safe_load(f))

    print(f"Splitting configurations for target {ARGS.project_id}: {build_configs_repo}, {meta.sanitizers}")
    configs = {}
    for architecture in meta.architectures:
        if architecture not in SUPPORTED_ARCHES:
            continue

        print(f"Splitting configurations for target {ARGS.project_id}: {architecture}")
        for sanitizer in meta.sanitizers:
            if sanitizer not in SUPPORTED_SANITIZERS:
                continue
            print(f"Splitting configurations for target {ARGS.project_id}: {sanitizer}")
            model = BuildConfiguration(
                project_id=ARGS.project_id,
                project_name = meta.get_project_name(),
                sanitizer=sanitizer,
                architecture=architecture,
            )
            config_key = build_configs_repo.upload_dedup(model.model_dump_json(indent=2))
            configs[config_key] = model
            print(f"Uploaded config {config_key}: {model}")

    metadata = {
        'num_build_configs': len(configs),
        'build_config_keys': list(configs.keys()),
        'harness_infos': {},
        'project_harness_metadatas': {},
        'build_configurations': {k: json.loads(v.model_dump_json()) for k, v in configs.items()},
    }
    if ARGS.include_harness_splitting:
        assert harness_infos_repo is not None, "Harness info repo should be set if splitting harnesses"
        assert project_harness_metadatas_dir is not None, "Harness coverage info repo should be set if splitting harnesses"


        project_harness_metadata_keys = set()
        for harness in meta.harnesses:
            print(f"Splitting harnesses for target {ARGS.project_id}: {meta.harnesses}")
            project_harness_metadata = {
                'project_id': ARGS.project_id,
                'project_name': meta.get_project_name(),
                'cp_harness_name': harness,
                'cp_harness_binary_path': Path('out/') / harness,
            }
            model_harness_meta = ProjectHarnessMetadata(
                **project_harness_metadata
            )
            project_harness_metadata_key = project_harness_metadatas_dir.upload_dedup(model_harness_meta.model_dump_json(indent=2))
            print(f"Uploaded harness metadata {project_harness_metadata_key}: {model_harness_meta}")
            project_harness_metadata_keys.add(project_harness_metadata_key)
            metadata['project_harness_metadatas'][project_harness_metadata_key] = json.loads(model_harness_meta.model_dump_json())


        harness_info_keys = set()
        for config_key, config in configs.items():
            print(f"Splitting harnesses for target {ARGS.project_id} for config {config_key} {meta.harnesses}")
            for harness_key, project_harness_metadata in metadata['project_harness_metadatas'].items():
                print(f"Splitting harnesses for target {ARGS.project_id} for config {config_key} {meta.harnesses}")
                model = HarnessInfo(
                    build_configuration_id=config_key,
                    project_harness_metadata_id=harness_key,
                    **project_harness_metadata, # already has the project_id and project_name as well as the harness name and binary path
                    **config.build_info,    # now add the
                )
                harness_info_key = harness_infos_repo.upload_dedup(model.model_dump_json(indent=2))
                print(f"Uploaded harness info {harness_info_key}: {model}")
                harness_info_keys.add((config_key, harness, harness_info_key))
                metadata['harness_infos'][harness_info_key] = json.loads(model.model_dump_json())

        metadata['num_harnesses'] = len(meta.harnesses)
        metadata['num_harness_infos'] = len(harness_info_keys)
        metadata['num_project_harness_metadatas'] = len(project_harness_metadata_keys)
        metadata['harness_info_keys'] = [x[-1] for x in harness_info_keys]

    with open(ARGS.target_split_metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

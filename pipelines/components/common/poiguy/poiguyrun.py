import argparse
import logging
import time

import yaml

from ASAN import dump_asn_poi
from AuditFunction import opwnaiaudit_file_parser_and_poi_dump
from CodeQl import code_ql_sarif_parser, code_ql_poi_dump
from DDFA import ddfa_file_parser, ddfa_poi_dump
from Jazzer import dump_jazzer_poi
from Joern import joern_file_parser, joern_poi_dump
from JoernCompile import compile_joern_data_base, find_function
from Mango import mango_file_parser, mango_poi_dump
from Semgrep import semgrep_sarif_parser, semgrep_poi_dump
from Snyk import snyk_sarif_parser, snyk_poi_dump
from Syzkaller import dump_syzkaller_poi
from iLLMutable import illmutable_file_parser_and_poi_dump

logging.basicConfig(format="%(levelname)s | %(asctime)s | %(message)s")
logging.getLogger().setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str, help='name of the target', required=True)
    parser.add_argument('--harness-info-id', type=str, help='harness info id', required=True)
    parser.add_argument('--scanner', type=str, help='name of the experiment', required=True)
    parser.add_argument('--scan_report_dir', type=str, help='dir for the scan reports', required=True)
    parser.add_argument('--joern_db', type=str, help='dir to the jorn files',
                        default='joern', required=False)  # deprecated, will be removed
    parser.add_argument('--index_csv_path', type=str, help='dir to the clang index files', default='index',
                        required=False)  # will be changed required=False -> required=True
    parser.add_argument('--poi_normalized_dir', type=str, help='dir for the normalized report from poi guy',
                        required=True)
    parser.add_argument('--crash_description', type=str, help='dir for the crash description', required=False,
                        default='')
    parser.add_argument('--crash_report_id', type=str, help='dir for the crash report id', required=False, default=None)
    parser.add_argument('--harness_id', type=str, help='ID of the harness in the project.yaml', required=False,
                        default=None)
    parser.add_argument('--target_metadata', type=str, help='metadata of the target', required=False, default=None)

    args = parser.parse_args()
    TARGET = args.target
    SCANNER = args.scanner
    SCAN_DIR = args.scan_report_dir
    POI_DIR = args.poi_normalized_dir
    JOERN_DB = args.joern_db  # deprecated, will be removed and replaced fully with INDEX_CSV
    INDEX_CSV_PATH = args.index_csv_path
    CRASH_DESCRIPTION = args.crash_description
    REPORT_ID = args.crash_report_id
    HARNESS_ID = args.harness_id
    TARGET_METADATA = args.target_metadata

    try:
        if SCANNER == 'codeql':
            jdb = compile_joern_data_base(joern_data_base_dir=JOERN_DB)
            logging.info('Joern functions DB compiled')
            codeqldb = code_ql_sarif_parser(codeql_file_path=SCAN_DIR)
            logging.info('CodeQL DB compiled')
            codeqldb_compiled = find_function(joern=jdb, db=codeqldb)
            logging.info('CodeQL DB synced with Joern DB')
            code_ql_poi_dump(codeql_db=codeqldb_compiled, poi_dir=POI_DIR, target=TARGET)
            logging.info('CodeQL POIs dumped')

        elif SCANNER == 'semgrep':
            jdb = compile_joern_data_base(joern_data_base_dir=JOERN_DB)
            logging.info('Joern functions DB compiled')
            semdb = semgrep_sarif_parser(semgrep_file_path=SCAN_DIR)
            logging.info('Semgrep DB compiled')
            semdb_compiled = find_function(joern=jdb, db=semdb)
            logging.info('Semgrep DB synced with Joern DB')
            semgrep_poi_dump(sem_db=semdb_compiled, poi_dir=POI_DIR, target=TARGET)
            logging.info('Semgrep POIs dumped')

        elif SCANNER == 'snyk':
            jdb = compile_joern_data_base(joern_data_base_dir=JOERN_DB)
            logging.info('Joern functions DB compiled')
            snykdb = snyk_sarif_parser(snyk_file_path=SCAN_DIR)
            logging.info('Snyk DB compiled')
            snykdb_compiled = find_function(joern=jdb, db=snykdb)
            logging.info('Snyk DB synced with Joern DB')
            snyk_poi_dump(snyk_db=snykdb_compiled, poi_dir=POI_DIR, target=TARGET)
            logging.info('Snyk POIs dumped')

        elif SCANNER == 'joern':
            joern = joern_file_parser(joern_file_path=SCAN_DIR)
            logging.info('Joern vulnerable functions DB compiled')
            joern_poi_dump(joern_db=joern, poi_dir=POI_DIR, target=TARGET)
            logging.info('Joern POIs dumped')

        elif SCANNER == 'mango':
            mango = mango_file_parser(mango_file_path=SCAN_DIR)
            logging.info('Mango DB compiled')
            mango_poi_dump(mango_db=mango, poi_dir=POI_DIR, target=TARGET)
            logging.info('Mango POIs dumped')

        elif SCANNER == 'ddfa':
            ddfa = ddfa_file_parser(ddfa_file_path=SCAN_DIR)
            logging.info('DDFA DB compiled')
            ddfa_poi_dump(ddfa_db=ddfa, poi_dir=POI_DIR, target=TARGET)
            logging.info('DDFA POIs dumped')

        elif SCANNER == 'opwnaiaudit':
            opwnaiaudit_file_parser_and_poi_dump(opwnaiaudit_dir=SCAN_DIR, poi_dir=POI_DIR, target=TARGET)
            logging.info('Opwnaiaudit POIs dumped')

        elif SCANNER == 'asan':
            dump_asn_poi(target_id=TARGET, asan_crash_report=SCAN_DIR,
                         clang_index_csv=INDEX_CSV_PATH, poi_reports_dir=POI_DIR)
            logging.info('ASAN POIs dumped')

        elif SCANNER == 'illmutable':
            illmutable_file_parser_and_poi_dump(illmutable_dir=SCAN_DIR, poi_dir=POI_DIR, target=TARGET)

        elif SCANNER == 'syzkaller':
            # target_id, crash_report_path, crash_description, clang_index_csv, poi_reports_dir
            dump_syzkaller_poi(target_id=TARGET, crash_report=SCAN_DIR, crash_report_id=REPORT_ID,
                               poi_reports_dir=POI_DIR, clang_index_csv=INDEX_CSV_PATH)

        elif SCANNER == 'jazzer':
            dump_jazzer_poi(target_id=TARGET, jazzer_crash_report=SCAN_DIR, crash_report_id=REPORT_ID,
                            antler4_index_csv=INDEX_CSV_PATH, poi_reports_dir=POI_DIR, harness_id=HARNESS_ID,
                            target_metadata=TARGET_METADATA)
    except Exception as e:
        logging.error(f'Error: {e}', exc_info=True)
        with open(
                f'{args.poi_normalized_dir}/poi-report-{args.scanner}-{args.target}-{args.crash_report_id}-{time.time()}.yaml',
                'w') as poi_file:
            yaml.safe_dump({
                'target_id': args.target,
                'harness_info_id': args.harness_info_id,
            }, poi_file)
        raise


# Entry point
if __name__ == '__main__':
    main()

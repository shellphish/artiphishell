#!/usr/bin/env python3
import argparse
from pathlib import Path

from patchery.testing import extract_patchery_files_from_backup


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        Convert the backup we get from test case to a resources for local run
        """,
        epilog="""
        Examples:
        ./backup_to_testfiles.py --backup /path/to/backup.tar.gz --output-dir ./tests/aicc_testing/mock_cp/
        """,
    )

    parser.add_argument(
        "--backup",
        type=Path,
        help="""
        The path of backup tar
        """,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="""
        The resource directory you want the resources from backup put into
        """,
    )
    parser.add_argument(
        "--overwrite",
        default=False,
        help="""
        If used, it will overwrite ever matching hashed backup data dir. 
        """,
    )

    args = parser.parse_args()
    extract_patchery_files_from_backup(args.backup, args.output_dir, overwrite=args.overwrite)

from datetime import datetime
import glob
import hashlib
from pathlib import Path
import time
from typing import List
from analysis_graph.models.harness_inputs import EPOCH_DATETIME, FuzzerQueueEntry, HarnessInputNode
from neomodel import db
from neomodel import StructuredNode, StructuredRel, RelationshipTo, RelationshipFrom
from neomodel import StringProperty, BooleanProperty, IntegerProperty, DateTimeProperty, JSONProperty, RegexProperty, ArrayProperty
import pytz

from analysis_graph.models import HarnessNode
from analysis_graph.models.fuzzers import KNOWN_FUZZER_NAMES, KNOWN_FUZZER_NAMES_PROPERTY_CHOICES

def filtered_sorted_seeds(paths, last_id=None):
    def seed_index(path: Path):
        full_name = path.name
        assert full_name.startswith('id:')
        index = full_name.split(',', 1)[0]
        return int(index.split("id:")[1])
    def cond(p):
        return p.is_file() and p.name != 'README.txt' and (last_id is None or seed_index(p) > last_id)
    # import ipdb; ipdb.set_trace()
    return list(sorted([path for path in paths if cond(path)], key=seed_index))

def parse_afl_seed_name(fuzzer, cur_instance, full_name: str):
    assert full_name.startswith('id:')
    index, *fields = full_name.split(',')
    index = int(index.split("id:")[1])

    vals = {}
    source_inputs = []
    for field in fields:
        if ':' not in field:
            assert field == '+cov'
            vals['new_coverage'] = True
            continue
        key, value = field.split(':', 1)
        vals[key] = value

    if 'sync' in vals:
        other_instance_name = vals['sync']
        assert 'src' in vals
        assert '+' not in vals['src']
        source_inputs += [{'fuzzer': fuzzer, 'fuzzer_instance_name': other_instance_name, 'index': int(vals['src']), 'crashing': False}]
    elif 'op' in vals and vals['op'] == 'splice':
        assert 'src' in vals
        assert '+' in vals['src']
        src_indices = [int(i) for i in vals['src'].split('+')]
        source_inputs += [{'fuzzer': fuzzer, 'fuzzer_instance_name': cur_instance, 'index': i, 'crashing': False} for i in src_indices]
    elif 'orig' in vals:
        assert 'src' not in vals
    else:
        assert 'src' in vals 
        assert '+' not in vals['src']
        source_inputs += [{'fuzzer': fuzzer, 'fuzzer_instance_name': cur_instance, 'index': int(vals['src']), 'crashing': False}]
    return index, fields, vals, source_inputs

def sync_afl_fuzzer_dir(target_vals, harness_info_vals, fuzzer: str, sync_dir: Path, last_crash_id=None, last_seed_id=None) -> List[HarnessInputNode]:
    def process_entries(dir, last_id=None, crashing=False):
        harness_input_data = []
        input_paths = filtered_sorted_seeds(dir.glob('id:*'), last_id=last_id)
        entries = []
        seed_sources = []
        for path in input_paths:
            print(f"Processing {path}")
            full_name = path.name
            assert full_name.startswith('id:')
            index, fields, vals, source_inputs = parse_afl_seed_name(fuzzer, instance_name, full_name)

            with open(path, 'rb') as f:
                content = f.read()
            content_hex = content.hex()
            content_escaped = repr(content)
            hash = hashlib.sha256(content).hexdigest()

            harness_input_data.append({
                **target_vals,
                **harness_info_vals,
                'content_hash': hash,
                'content_hex': content_hex,
                'content_escaped': content_escaped,
                'crashing': crashing,
            })
            entries.append({
                **target_vals,
                **harness_info_vals,
                'fuzzer': fuzzer,
                'crashing': crashing,
                'identifier': f'{fuzzer}:{instance_name}:{index}',
                'fuzzer_instance_name': instance_name,
                'index': index,
                'full_name': full_name,
                'fields': fields,
                'new_coverage': vals.get('new_coverage', False),
            })
            for source_input in source_inputs:
                src = {
                    **target_vals,
                    **harness_info_vals,
                    **source_input,
                }
                cur = {
                    **target_vals,
                    **harness_info_vals,
                    'identifier': f'{fuzzer}:{instance_name}:{index}',
                    'fuzzer': fuzzer,
                    'fuzzer_instance_name': instance_name,
                    'index': index,
                    'crashing': crashing,
                }
                seed_sources.append((src, cur))

        harness_inputs = HarnessInputNode.get_or_create(
            *harness_input_data,
        )
        with db.transaction:
            for harness_input, path in zip(harness_inputs, input_paths):
                if not harness_input.first_discovered_fuzzer:
                    harness_input.first_discovered_fuzzer = fuzzer
                if harness_input.first_discovered_timestamp == EPOCH_DATETIME:
                    harness_input.first_discovered_timestamp = datetime.utcfromtimestamp(path.stat().st_ctime).replace(tzinfo=pytz.utc)
                harness_input.save()
                
        entries = FuzzerQueueEntry.create_or_update(
            *entries
        )
        for entry, harness_input in zip(entries, harness_inputs):
            entry.fuzz_input.connect(harness_input)
        for src, cur in seed_sources:
            src_entry, = FuzzerQueueEntry.get_or_create(src)
            cur_entry, = FuzzerQueueEntry.get_or_create(cur)
            cur_entry.source_input.connect(src_entry)

        return list(zip(entries, harness_inputs))

    assert (sync_dir / 'queue').is_dir()
    instance_name = sync_dir.name

    seeds = process_entries(sync_dir / 'queue', crashing=False, last_id=last_seed_id)
    if (sync_dir / 'crashes').is_dir():
        crashes = process_entries(sync_dir / 'crashes', crashing=True, last_id=last_crash_id)
    else:
        crashes = []

    return seeds, crashes

def monitor_afl_fuzzer_dir(target_vals, harness_info_vals, fuzzer: str, sync_dir: Path, monitor_interval: int):
    last_seed_id = None
    last_crash_id = None
    while True:
        seeds, crashes = sync_afl_fuzzer_dir(target_vals, harness_info_vals, fuzzer, sync_dir)
        print(f"Synced {len(seeds)} new seeds and {len(crashes)} new crashes")
        for seed_entry, harness_input in seeds:
            print(f"Seed {seed_entry.index} -> {harness_input.content_hash}")
        for crash_entry, harness_input in crashes:
            print(f"Crash {crash_entry.index} -> {harness_input.content_hash}")

        if seeds:
            prev_last_seed_id = last_seed_id
            last_seed_id = max(seed.index for seed, _ in seeds)
            print(f"Last seed ID: {prev_last_seed_id} -> {last_seed_id}")
        if crashes:
            prev_last_crash_id = last_crash_id
            last_crash_id = max(crash.index for crash, _ in crashes)
            print(f"Last crash ID: {prev_last_crash_id} -> {last_crash_id}")

        if monitor_interval is None:
            break
        time.sleep(monitor_interval)
        
def main():
    import argparse
    import logging

    parser = argparse.ArgumentParser(description='Handle harness inputs')
    subcommand = parser.add_subparsers(dest='subcommand', required=True)
    
    monitor_afl_dir_subcommand = subcommand.add_parser('monitor', help='Monitor AFL sync dir harness inputs')
    monitor_afl_dir_subcommand.add_argument('-i', '--monitor-interval', type=int, default=None, help='How often to check for new inputs, if unset do a single pass and exit')
    monitor_afl_dir_subcommand.add_argument('pdt_project_id', type=str, help='The PDT target ID')
    monitor_afl_dir_subcommand.add_argument('target_name', type=str, help='The target name')
    monitor_afl_dir_subcommand.add_argument('pdt_harness_info_id', type=str, help='The PDT harness info ID')
    monitor_afl_dir_subcommand.add_argument('harness_name', type=str, help='The harness name')
    monitor_afl_dir_subcommand.add_argument('fuzzer', type=str, help='The fuzzer name', choices=[n for n in KNOWN_FUZZER_NAMES if n])
    monitor_afl_dir_subcommand.add_argument('sync_dir', type=Path, help='Sync dir of the fuzzer instance you want to sync (must contain queue/ and crashes/)')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.subcommand == 'monitor':
        target_vals = {
            'pdt_project_id': args.pdt_project_id,
            'target_name': args.target_name,
        }
        harness_info_vals = {
            'pdt_harness_info_id': args.pdt_harness_info_id,
            'harness_name': args.harness_name,
        }

        monitor_afl_fuzzer_dir(target_vals, harness_info_vals, args.fuzzer, args.sync_dir, args.monitor_interval)


import logging
import os
import json
import time
import pickle
import traceback

from pathlib import Path
from tqdm.auto import tqdm

import gzip
import shutil
import git


from ..models.syzkaller import SyzProg, BasicBlock

DELIMITER = '\u27c2'


def parse_entry(coverage_entry):
    file_path = coverage_entry['filepath']
    function_name = coverage_entry['function_name']
    source_lines = BasicBlock.clean_up_source(coverage_entry['code'])
    bb_identifier = BasicBlock.get_identifier(file_path, function_name, source_lines)
    syzprog_source = coverage_entry['syzprog']
    syzprog_identifier = SyzProg.get_identifier(syzprog_source)
    commit = coverage_entry['linux_commit']
    line_no = coverage_entry['line_no']

    return bb_identifier, source_lines, file_path, function_name, commit, line_no, syzprog_identifier, syzprog_source 

def replace(s):
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s

def create_csv_from_syzprogs(syzprogs):

    lines = []
    header = f'identifier:ID(SyzProgs){DELIMITER}source{DELIMITER}:LABEL'
    for syzprog_identifier, syzprog_source in syzprogs.items():
        syzprog_source = replace(syzprog_source)
        row = f'{syzprog_identifier}{DELIMITER}"{syzprog_source}"{DELIMITER}SyzProg'
        lines.append(row)

    return header, '\n'.join(lines)

def create_csv_from_bbs(basic_blocks):
    lines = []
    header = f'identifier:ID(BasicBlocks){DELIMITER}function_name{DELIMITER}file_name{DELIMITER}source{DELIMITER}:LABEL'
    for bb_identifier, entry in basic_blocks.items():
        function_name, file_name, source_lines = entry['function'], entry['file'], entry['source_lines']

        source_lines = replace(source_lines)

        row = f'{bb_identifier}{DELIMITER}"{function_name}"{DELIMITER}"{file_name}"{DELIMITER}"{source_lines}"{DELIMITER}BasicBlock'
        lines.append(row)

    return header, '\n'.join(lines)

def create_csv_from_edges(relationships, commit_timestamps):

    lines = []
    header = f':START_ID(SyzProgs){DELIMITER}commit{DELIMITER}line_no{DELIMITER}commit_epoch{DELIMITER}:END_ID(BasicBlocks){DELIMITER}:TYPE'
    for rel_identifier, rel_commits in relationships.items():
        syzprog_identifier, bb_identifier, _, _ = rel_identifier.split(':')
        commit_sha, line_no = rel_commits.split('-')
        timestamp = commit_timestamps[commit_sha]

        row = f'{syzprog_identifier}{DELIMITER}{commit_sha}{DELIMITER}{line_no}{DELIMITER}{timestamp}{DELIMITER}{bb_identifier}{DELIMITER}SYZPROG_TRIGGERS_BASICBLOCK'
        lines.append(row)

    return header, '\n'.join(lines)

def process_file(filepath, output_path, repo, global_identifiers, commit_timestamps):

    init_time = time.time()

    filename = os.path.split(filepath)[1].split('.')[0]
    
    if os.path.isfile(os.path.join(output_path, f'{filename}_edges.csv.gz')):
        logging.info(f'{filepath} was already processed. Skipping...')
        return
    
    with open(filepath, 'r') as f:
        input_path = json.load(f, strict=False)['result']


    logging.info(f'Number of entries in the syzcoverage dataset (path: {filepath}, filename: {filename}): {len(input_path)}')

    # map from syzprog hash to syzprog source
    syzprogs = {}

    # map from basicblock hash to basic block details
    basic_blocks = {}
    
    # map from syzprog_hash::basic_block_hash to a list of tuples (commit, line_no)
    relationships = {}
    
    for entry in tqdm(input_path):

        try:
            bb_identifier, source_lines, file_path, function_name, commit, line_no, syzprog_identifier, syzprog_source = parse_entry(entry)
        except:
            continue
        
        if commit not in commit_timestamps:

            try:
                commit_timestamps[commit] = repo.commit(commit).committed_date
            except:
                commit_timestamps[commit] = -1


        if syzprog_identifier not in syzprogs and syzprog_identifier not in global_identifiers[0]:
            syzprogs[syzprog_identifier] = syzprog_source
            global_identifiers[0].add(syzprog_identifier)
        
        if bb_identifier not in basic_blocks and bb_identifier not in global_identifiers[1]:

            entry = {'function': function_name,
                    'file': file_path,
                    'source_lines': source_lines}
            
            basic_blocks[bb_identifier] = entry
            global_identifiers[1].add(bb_identifier)

        rel_identifier =  f'{syzprog_identifier}:{bb_identifier}:{commit}:{line_no}'
        commit_identifier = f'{commit}-{line_no}'

        if rel_identifier not in relationships and rel_identifier not in global_identifiers[2]:
            relationships[rel_identifier] = commit_identifier
            global_identifiers[2].add(rel_identifier)
        
    logging.info(f'Number of syzprogs: {len(syzprogs)} - Number of BBs: {len(basic_blocks)} - Number of Relationships: {len(relationships)}')
    
    for d, t in zip([syzprogs, basic_blocks, relationships], ['syzprogs', 'bbs', 'edges']):

        if t == 'syzprogs':
            header, csv = create_csv_from_syzprogs(d)

        elif t == 'bbs':
            header, csv = create_csv_from_bbs(d)

        elif t == 'edges':
            header, csv = create_csv_from_edges(d, commit_timestamps)

        csv_file = os.path.join(output_path, f'{filename}_{t}.csv')
        with open(csv_file, 'w') as fp:
            fp.write(csv)

        header_file = os.path.join(output_path, f'{filename}_{t}_header.csv')
        with open(header_file, 'w') as fp:
            fp.write(header)

        with open(csv_file, 'rb') as fp:
            with gzip.open(f'{csv_file}.gz', 'wb') as f_out:
                shutil.copyfileobj(fp, f_out)

        os.remove(csv_file)
        
    end_time = time.time()

    logging.info(f'Processing took: {end_time - init_time} seconds.')


def main():

    logging.basicConfig(level=logging.INFO)
    logging.info('Started')

    import argparse

    parser = argparse.ArgumentParser(description='Prepare the syzcoverage dataset for importing to to the knowledge base')
    parser.add_argument('--input_path', default='/data/suraj/Coverage-Information', 
                        help='The exported syzbot coverage dataset (Created by mzakocs by scraping Syzbot)')

    parser.add_argument('--output_path', default='./download/syzcoverage_processed', 
                        help='The output path for processed csvs')

    parser.add_argument('--global_identifiers',  default='./download/syzcoverage_processed/global_identifiers.pickle', 
                        help='the identifiers of all processed basic blocks and syzprogs.')

    parser.add_argument('--git_repo', help='Path to the git repo of Linux Kernel to import', default='./download/linux')

    args = parser.parse_args()

    repo = git.Repo(args.git_repo)

    args = parser.parse_args()

    Path(args.output_path).mkdir(exist_ok=True, parents=True)

    input_files = os.listdir(args.input_path)
    input_files = [os.path.join(args.input_path, f) for f in input_files if '.json' in f]

    logging.info(f'Found {len(input_files)} files to process in {args.input_path}')

    if not os.path.isfile(args.global_identifiers):
        global_identifiers = (set(), set(), set())

        with open(args.global_identifiers, 'wb') as fp:
            pickle.dump(global_identifiers, fp)

    with open(args.global_identifiers, 'rb') as fp:
        global_identifiers = pickle.load(fp)

    
    commit_timestamps = {}

    for filepath in input_files:
        try:
            process_file(filepath, args.output_path, repo, global_identifiers, commit_timestamps)
        except:
            logging.error(f'Error processing {filepath}')
            logging.error(traceback.format_exc())
            continue

    with open(args.global_identifiers, 'wb') as fp:
        pickle.dump(global_identifiers, fp)


# rsync ./download/syzcoverage_processed/* -Pav -e "ssh -i ~/windows_priv/id_rsa" Lukas-Dresel@beatty.unfiltered.seclab.cs.ucsb.edu:/home/Lukas-Dresel/lukas/aixcc/pipelines/apis/knowledge-base-kernel-data/import

# kb_prepare_syzcoverage --input_path /data/suraj/Coverage-Information --output_path ./download/syzcoverage_processed/

# neo4j-admin database import full --overwrite-destination=true --skip-bad-relationships=true --bad-tolerance=100000000 --multiline-fields=true --delimiter="U+27C2" --legacy-style-quoting=true --nodes="10000000_syzprogs_header.csv,.*_syzprogs.csv.gz" --nodes="10000000_bbs_header.csv,.*_bbs.csv.gz" --relationships="10000000_edges_header.csv,.*_edges.csv.gz" --verbose neo4j > import_admin.log 2>&1 &

'''
MATCH (m:SyzProg)--(n:BasicBlock) WHERE m.identifier = 'd73a5485585b3b752302b7ec814c5c4f'
RETURN  m, COLLECT(DISTINCT n.file_name)
'''

'''
MATCH (m:SyzProg)-[x:SYZPROG_TRIGGERS_BASICBLOCK]->(n:BasicBlock)
RETURN m, SIZE(COLLECT(n)) as bb_cnt
ORDER BY bb_cnt DESC LIMIT 10
'''


'''
MATCH (m:SyzProg)-[x:SYZPROG_TRIGGERS_BASICBLOCK]->(n:BasicBlock)
RETURN m, COLLECT(n) as triggered
ORDER BY SIZE(triggered) DESC LIMIT 10
'''
import argparse
from collections import Counter
from typing import List
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import numpy as np
from matplotlib import pyplot as plt
import re
import sys
import os
import pandas as pd

def parse_mutation_log(path='./.cov.tsv'):
    cov_timeline = []
    with open(path, 'r') as f:
        results = []
        cur_results = None
        # import ipdb; ipdb.set_trace()
        cur_bbs, cur_edges, cur_points = 0, 0, 0
        last_timestamp = 0
        over_time_results = []
        for line in f.readlines():
            line = line.replace('\0', '')
            line = line.strip()
            if not line:
                continue

            timestamp, bbs, edges, points = list(map(int, line.split('\t')))
            over_time_results.append({'timestamp': last_timestamp, 'cov': cur_result['cov'].copy(), 'successful_mutations': cur_result['successful_mutations'].copy()})
            # cur_result = {'cov': Counter({k: 0 for k in cur_result['cov']}), 'successful_mutations': Counter({k: 0 for k in cur_result['successful_mutations']})}

            cur_result['cov'][mutation_kind] += cov_after - cov_before
            cur_result['successful_mutations'][mutation_kind] += 1
            totals['cov_gained'][mutation_kind] += cov_after - cov_before
            totals['successful_mutations'][mutation_kind] += 1
            last_timestamp = timestamp
            cur_cov = cov_after

        cov_timeline.append({'timestamp': last_timestamp, 'cov': cur_cov})
        over_time_results.append({'timestamp': last_timestamp, 'cov': cur_result['cov'], 'successful_mutations': cur_result['successful_mutations']})

        final = []
        # import ipdb; ipdb.set_trace()
        for v in over_time_results:
            data = {'timestamp': v['timestamp']}
            for mutation, cov_count in v['cov'].items():
                data['cov_' + mutation] = cov_count
            for mutation, success_count in v['successful_mutations'].items():
                data['successful_mutations_' + mutation] = success_count
            final.append(data)

        last = final[-1]
        keys = ['timestamp'] + [k for k, v in sorted(last.items(), key=lambda x:x[1]) if k.startswith('cov_')] + [k for k, v in sorted(last.items(), key=lambda x:x[1]) if k.startswith('successful_mutations_')]
        return pd.DataFrame(final, columns=keys)

parser = argparse.ArgumentParser()
parser.add_argument('path', default='./.successful_symcts_mutations.tsv')
parser.add_argument('--only-coverage-gain', action='store_true', default=False, help='Only plot mutations actually resulting in coverage gain')
args = parser.parse_args()

results = parse_mutation_log(args.path, args.only_coverage_gain)
results['timestamp'] -= results['timestamp'].min()
results_cov = results[[k for k in results.columns if k.startswith('cov_') or k == 'timestamp']]
results_successful_mutations = results[[k for k in results.columns if k.startswith('successful_mutations_') or k == 'timestamp']]

results_cov.plot(x='timestamp', kind='line', title='Coverage over time')
plt.show()
results_successful_mutations.plot(x='timestamp', kind='line', title='Successful mutations over time')
plt.show()

for k in results.columns:
    if k == 'timestamp':
        continue
    if not k.startswith('cov_'):
        continue
    mutation = k[4:]
    results['cov_per_successful_mutations_' + mutation] = results[k] / results['successful_mutations_' + mutation]

results_cov_per_successful_mutations = results[[k for k in results.columns if k.startswith('cov_per_successful_mutations_') or k == 'timestamp']]
results_cov_per_successful_mutations.plot(x='timestamp', kind='line', title='Coverage per successful mutation over time')
plt.show()


results_cov.plot.area(x='timestamp')
plt.show()
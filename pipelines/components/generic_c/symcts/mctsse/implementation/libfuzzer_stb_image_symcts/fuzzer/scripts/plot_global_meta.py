from collections import Counter
import json
from logging import log
import logging
from typing import List
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import numpy as np
from matplotlib import pyplot as plt
import re
import sys
import os

# def parse_mutation_log(path='./successful_symcts_mutations.log'):
#     with open(path, 'r') as f:
#         results = []
#         cur_results = None
#         for line in f.readlines():
#             line = line.replace('\0', '')
#             line = line.strip()
#             if not line:
#                 continue

#             if line.startswith('######## '):
#                 if cur_results is not None:
#                     results.append(cur_results)

#                 cur_results = {
#                     'mutated_seed': int(line.split('CorpusID { id: ')[1].split(' } ')[0]),
#                     'successful_mutations': Counter()
#                 }
#                 continue

#             # if line is something else
#             mutation_type = line.split(' ')[0]
#             cur_results['successful_mutations'][mutation_type] += 1

#         if cur_results:
#             results.append(cur_results)
#         return results

# def bucket_mutation_counts(mutations: List[str], parsed, nsteps=20):

#     # import ipdb; ipdb.set_trace()
#     res = []
#     for i in range(0, len(parsed), nsteps):
#         if i + nsteps > len(parsed):
#             # the last bucket is incomplete, let's not include it in the plot
#             continue
#         cur_accum = [0] * len(mutations)
#         for j, cur_results in enumerate(parsed[i:i+nsteps]):
#             for mut_idx, mut in enumerate(mutations):
#                 cur_accum[mut_idx] += cur_results['successful_mutations'][mut]
#         res.append(cur_accum)
#     return res

# def moving_average(mutations: List[str], parsed, nsteps=10):
#     window_per_mut = [[0 for _ in range(nsteps)] for _ in range(len(mutations))]
#     results = []
#     for i, cur_results in enumerate(parsed):
#         for mut_idx, mut in enumerate(mutations):
#             window_per_mut[mut_idx][i % nsteps] = cur_results['successful_mutations'][mut]

#         results.append([sum(window_per_mut[mut_idx]) / nsteps for mut_idx, mut in enumerate(mutations)])
#     return results

# def accumulated_sum(mutations: List[str], parsed):
#     results = []
#     cur = [0] * len(mutations)
#     for i, cur_results in enumerate(parsed):
#         for mut_idx, mut in enumerate(mutations):
#             cur[mut_idx] += cur_results['successful_mutations'][mut]

#         results.append(list(cur))
#     return results


# parsed = parse_mutation_log(sys.argv[1] if len(sys.argv) > 1 else './successful_symcts_mutations.log')
# mutation_names = list(sorted({ mutation for result in parsed for mutation in result['successful_mutations'].keys() }))
# # parsed = list(sorted(parsed, key=lambda x: sum(x['successful_mutations'].values())))
# # accum = bucket_mutation_counts(mutation_names, parsed, nsteps=3)
# accum = moving_average(mutation_names, parsed, nsteps=10)
# # accum = accumulated_sum(mutation_names, parsed)

# for index, mutation in enumerate(mutation_names):
#     plt.plot([x[index] for x in accum], label=mutation)

# plt.legend()
# plt.show()


# accum_percent = []
# for x in accum:
#     total = sum(x)
#     if total == 0:
#         accum_percent.append(x)
#     else:
#         accum_percent.append([y / total for y in x])

# interpret each 3-length array in accum as a 3d point
# and plot it
# fig = plt.figure()
# ax = fig.add_subplot(111, projection='3d')
# xs = [x[0] for x in accum]
# ys = [x[1] for x in accum]
# zs = [x[2] for x in accum]
# ax.scatter(xs, ys, zs, c='r', marker='o')
# ax.set_xlabel(mutations[0])
# ax.set_ylabel(mutations[1])
# ax.set_zlabel(mutations[2])
# plt.show()

# plot 2-d pca of accum
# pca = PCA(n_components=2)
# accum_pca = pca.fit_transform(np.array(accum))
# plt.scatter(accum_pca[:, 0], accum_pca[:, 1])
# plt.show()


# compute t-sne of the accumulated mutation counts
# tsne = TSNE(n_components=2, learning_rate='auto', init='random', perplexity=3)
# X_embedded = tsne.fit_transform(np.array(accum))
# plt.scatter(X_embedded[:, 0], X_embedded[:, 1])
# plt.show()

GLOBAL_META_DIR = sys.argv[1]
seen_branches = set()
seen_coverage_points = set()
new_data = []
steps_branches = []
steps_coverage_points = []
for i, f in list(enumerate(sorted(os.listdir(GLOBAL_META_DIR)))):
    if not f.endswith('.json'):
        log(logging.WARN, f'ignoring {f}')
        continue
    with open(os.path.join(GLOBAL_META_DIR, f), 'r') as file:
        data = json.load(file)
    times_traced = Counter()
    times_symbolically_sampled = Counter()
    new_branches = {k.split(' * ')[0]: cur_data for k, cur_data in data.items() if k.split(' * ')[0] not in seen_branches}
    seen_coverage_points.update(data.keys())
    for k, cur_data in new_branches.items():
        times_traced[k] += cur_data['num_times_coverage_traced']
        times_symbolically_sampled[k] += cur_data['num_times_symbolically_sampled']

        k = k.split(' * ')[0]
        seen_branches.add(k)

    new_data.append(new_branches)
    steps_branches.append(len(seen_branches))
    steps_coverage_points.append(len(seen_coverage_points))

# plot steps_branches and steps_coverage_points on the left and right
# y axis respectively
fig, ax1 = plt.subplots()
ax1.plot(steps_branches, 'b-')
ax1.set_xlabel('steps')
# Make the y-axis label, ticks and tick labels match the line color.
ax1.set_ylabel('branches', color='b')
ax1.tick_params('y', colors='b')
ax1.set_yscale('log')
ax1.set_xscale('log')

ax2 = ax1.twinx()
ax2.plot(steps_coverage_points, 'r-')
ax2.set_ylabel('coverage points', color='r')
ax2.tick_params('y', colors='r')
ax2.set_yscale('log')
ax2.set_xscale('log')

fig.tight_layout()
print(steps_branches[:20])
print(steps_coverage_points[:20])

plt.show()
# plt.show()

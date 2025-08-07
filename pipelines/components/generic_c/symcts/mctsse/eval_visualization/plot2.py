# IPython log file

import json
from collections import Counter
from matplotlib import pyplot as plt
counts = json.load(open('branch_counts.json'))
all_branches = {branch for node, branch_counts in counts.items() for branch in branch_counts}

fig, axes = plt.subplots(2,2)
for i, (node, branch_counts) in enumerate(counts.items()):
    full_counts = {b: 0 for b in all_branches}
    full_counts.update(branch_counts)
    sort = list(sorted(full_counts.values()))
    ax = axes[i//2, i%2]
    ax.set_yscale('log')
    ax.plot(sort)
    ax.set_title(node)

plt.show()

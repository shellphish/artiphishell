# IPython log file

import json
import sys
from collections import Counter
from matplotlib import pyplot as plt
counts = json.load(open('branch_counts.json'))
all_branches = {branch for node, branch_counts in counts.items() for branch in branch_counts}

sorted_branches = [branch for branch, cnt in sorted(counts[sys.argv[1]].items(), key=lambda x: x[::-1])]
fig, axes = plt.subplots(2,2)
for i, (node, branch_counts) in enumerate(counts.items()):
    data = [branch_counts.get(b, 0) for b in sorted_branches]
    ax = axes[i//2, i%2]
    ax.set_yscale('log')

    ax.plot(data, color=['green', 'red', 'blue', 'yellow'][i])
    ax.set_title(node)

plt.show()

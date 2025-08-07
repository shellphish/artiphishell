# IPython log file

import json
import sys
from collections import Counter
from matplotlib import pyplot as plt
def flatten(*args):
    for xs in args:
        for x in xs:
            yield x
counts = json.load(open('branch_counts.json'))
nodes = list(sorted(counts.keys()))
branches = set(flatten(*[counts[n] for n in nodes]))
merged_counts = Counter()
for node, branches in counts.items():
    merged_counts.update(branches)

#branch_counts = [(branch,) + tuple(counts[node].get(branch, 0) for node in nodes) for branch in branches]
sorted_counts = list(sorted(merged_counts.items(), key=lambda x: x[::-1]))
sorted_branches = [x[0] for x in sorted_counts]

def plot_individuals(node, branch_counts, axis):
    data = [branch_counts.get(b, 0) for b in sorted_branches]
    axes[i//2,i%2].set_yscale('log')
    
    axes[i//2,i%2].plot(data, color=['green', 'red', 'blue', 'orange'][i])
    axes[i//2,i%2].set_title(node)

def plot_combineds(axis):
    sorted_counts = [merged_counts.get(b, 0) for b in sorted_branches]
    axis.plot(sorted_counts, color='black')
#ax[2,0].set_yscale('log')
#ax[2,0].set_title('Combined')


fig, ax = plt.subplots(1,1)
style='.'
for i, (node, branch_counts) in enumerate(counts.items()):
    data = [branch_counts.get(b, 0) for b in sorted_branches]
    ax.plot(data, ['g', 'r', 'b', 'm'][i] + style)

plot_combineds(ax)
ax.set_title('Combined')
#ax.set_yscale('log')
fig.show()
sorted_merged_counts = [merged_counts.get(b, 0) for b in sorted_branches]

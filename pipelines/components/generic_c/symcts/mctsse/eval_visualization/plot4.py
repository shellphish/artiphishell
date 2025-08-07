# IPython log file

import json
from collections import Counter
from matplotlib import pyplot as plt
counts = json.load(open('branch_counts.json'))
all_branches = {branch for node, branch_counts in counts.items() for branch in branch_counts}

merged_counts = Counter()
for node, branches in counts.items():
    merged_counts.update(branches)
sorted_counts = [cnt for branch, cnt in list(sorted(counts['slave2'].items(), key=lambda x: x[::-1]))]
fig, axes = plt.subplots(1,1)
axes.plot(sorted_counts)
axes.set_yscale('log')
axes.set_title('Combined')

plt.show()

# IPython log file

import json
from collections import Counter
from matplotlib import pyplot as plt
counts = json.load(open('branch_counts.json'))
by_node = {node: Counter(counts.values()) for node, counts in counts.items()}

cnt_occurrences = {node: list(sorted(branch_counts.items())) for node, branch_counts in by_node.items()}
fig, axes = plt.subplots(2,2)

axes[0,0].plot(*zip(*cnt_occurrences['master']))
axes[0,0].set_title('deterministic')
axes[0,1].plot(*zip(*cnt_occurrences['slave0']))
axes[0,1].set_title('havoc0')
axes[1,0].plot(*zip(*cnt_occurrences['slave1']))
axes[1,0].set_title('havoc1')
axes[1,1].plot(*zip(*cnt_occurrences['slave2']))
axes[1,1].set_title('havoc2')
plt.show()

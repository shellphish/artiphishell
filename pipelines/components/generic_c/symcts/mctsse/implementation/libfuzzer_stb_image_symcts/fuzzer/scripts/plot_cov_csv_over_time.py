import argparse
from collections import Counter, defaultdict
from typing import List
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import numpy as np
from matplotlib import pyplot as plt
import re
import sys
import os
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument('output_dir', type=str, help='Path to the output directory')
parser.add_argument('path', type=str, help='Path to the coverage CSV file with timestamp and coverage column')
parser.add_argument('--save-only', action='store_true', help='Only save the plot, do not show it')
args = parser.parse_args()
os.makedirs(args.output_dir, exist_ok=True)

name = os.path.basename(args.path)
if name.endswith('.csv'):
    name = name[:-4]
else:
    raise ValueError('Path must end with .csv')

results = pd.read_csv(args.path, sep=', ')
results['timestamp'] -= results['timestamp'].min()

label_groups = defaultdict(list)
group_for_column = {}

col_labels = [label for label in results.columns[1:]]
for label in col_labels:
    # label group is without _{int} suffix
    label_group = label.rstrip('-_0123456789')
    label_groups[label_group].append(label)
    group_for_column[label] = label_group


label_group_names = sorted(label_groups.keys())

# get a colormap for the label_groups
cmap = plt.get_cmap('plasma')
colors = cmap(np.linspace(0, 1, len(label_group_names)))
col_colors = [colors[label_group_names.index(group_for_column[col_label])] for col_label in col_labels]
col_dashing = ['-' if group_for_column[col_label] == col_label else '-.' for col_label in col_labels]
col_labels = [col_label if group_for_column[col_label] == col_label else '_' for col_label in col_labels]

# remove consecutive entries with the same cov value, leaving only the first one
results = results.drop_duplicates(subset='timestamp', keep='last')
ax = results.plot(x='timestamp', kind='line', title='Coverage over time', color=col_colors, style=col_dashing)
ax.set_facecolor("lightgray")
ax.legend(col_labels)
plt.savefig(os.path.join(args.output_dir, '{}_coverage_over_time.png'.format(name)))
if not args.save_only:
    plt.show()

# plot only the labels of this label group
labels_to_plot = label_group_names
cmap = plt.get_cmap('plasma')
colors = cmap(np.linspace(0, 1, len(labels_to_plot)))
col_colors = [colors[i] for i, col_label in enumerate(labels_to_plot)]
col_dashing = ['-' if group_for_column[col_label] == col_label else '-.' for col_label in labels_to_plot]
ax = results.plot(x='timestamp',
                    y=labels_to_plot,
                    kind='line',
                    title='Coverage over time (Combined)',
                    color=col_colors,
                    style=col_dashing
)
ax.set_facecolor('lightgray')
plt.savefig(os.path.join(args.output_dir, '{}_coverage_over_time_combined.png'.format(name)))
if not args.save_only:
    plt.show()

# for label_group in label_group_names:
#     # plot only the labels of this label group
#     labels_to_plot = label_groups[label_group]
#     cmap = plt.get_cmap('plasma')
#     colors = cmap(np.linspace(0, 1, len(labels_to_plot)))
#     col_colors = [colors[i] for i, col_label in enumerate(labels_to_plot)]
#     col_dashing = ['-' if group_for_column[col_label] == col_label else '-.' for col_label in labels_to_plot]
#     ax = results.plot(x='timestamp',
#                       y=labels_to_plot,
#                       kind='line',
#                       title='Coverage over time ({})'.format(label_group),
#                       color=col_colors,
#                       style=col_dashing
#     )
#     ax.set_facecolor('lightgray')
#     plt.show()


# plot confidence bands for each label_group
per_label_group = pd.DataFrame()
fig = plt.figure()
labels_to_plot_per_group = []
for label_group in label_group_names:
    labels = [l for l in label_groups[label_group] if l != label_group]
    if not labels:
        continue
    labels_to_plot_per_group.append((label_group, labels))

ax = fig.subplots(ncols=1, nrows=1, sharex=True, sharey=True)
colors = cmap(np.linspace(0, 1, len(labels_to_plot_per_group)))

handles = []
for (i, ((label_group, labels), ax)) in enumerate(zip(labels_to_plot_per_group, [ax for _ in range(len(labels_to_plot_per_group))])):
    # average of all labels in the group per timestamp
    mean = results[labels].mean(axis=1)
    # standard deviation of all labels in the group per timestamp
    std = results[labels].std(axis=1)
    # 95% confidence band = 1.96 * std
    mean = mean
    lower = mean - std
    upper = mean + std
    min = results[labels].min(axis=1)
    max = results[labels].max(axis=1)
    ax.plot(results['timestamp'], mean, color=colors[i], linestyle='--')
    ax.fill_between(results['timestamp'], min, max, alpha=0.3, color=colors[i])
    # ax.fill_between(results['timestamp'], lower, upper, alpha=0.2, color=colors[i])
    ax.set_title(label_group)
    ax.plot(results['timestamp'], results[label_group], color=colors[i], label=label_group)
    ax.set_facecolor('lightgray')
ax.legend()

plt.savefig(os.path.join(args.output_dir, '{}_coverage_over_time_confidence_bands.png'.format(name)))
if not args.save_only:
    plt.show()
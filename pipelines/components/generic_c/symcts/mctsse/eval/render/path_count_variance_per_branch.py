import json
import matplotlib.pyplot as plt
from collections import defaultdict
import numpy as np
import sys

with open(sys.argv[1], 'r') as f:
    d = json.load(f)

by_addr = []
for node_name, per_block_path_counts in d.items():
    branch_indices = {}
    per_branch_stats = defaultdict(dict)
    variances = []
    indices_of_dispersion = []
    coefficients_of_variation = []
    relative_deviations = []
    max_over_total = []
    max10_over_total = []
    ninety_percentile_over_total = []
    percent_of_branches_comprising_upper_90percent = []
    for block_addr, path_counts in per_block_path_counts.items():
        by_addr.append(block_addr)
        addr_index = len(by_addr) - 1
        all_items = list(path_counts.items())
        counts_array = np.array([cnt for _, cnt in all_items])
        # print(f"{counts_array=}")
        exec_count_variance = np.var(counts_array)
        # print(f"{block_addr=}, {exec_count_variance=}")

        total_path_execution_count = np.sum(counts_array)
        # print(f"{total_path_execution_count=}")
        avg_path_exec_count = total_path_execution_count / len(all_items)
        # print(f"{avg_path_exec_count=}")
        deviations_from_mean = counts_array - avg_path_exec_count
        # print(f"{deviations_from_mean=}")

        squared_deviation_from_mean = deviations_from_mean**2
        # print(f"{squared_deviation_from_mean=}")

        mean_squared_deviation_from_mean = np.mean(squared_deviation_from_mean)
        # print(f"{mean_squared_deviation_from_mean=}")

        variances.append(mean_squared_deviation_from_mean)

        # variance over mean = Index of Dispersion (https://en.wikipedia.org/wiki/Index_of_dispersion)
        # discussion: https://stats.stackexchange.com/questions/203766/use-cases-for-coefficient-of-variation-vs-index-of-dispersion
        indices_of_dispersion.append(mean_squared_deviation_from_mean / avg_path_exec_count)
        coefficients_of_variation.append(
            np.std(counts_array) / np.mean(counts_array)
        )
        relative_deviations.append(np.std(counts_array) / np.sum(counts_array))

        max_over_total.append(np.max(counts_array) / total_path_execution_count)
        max10_over_total.append(np.sum(np.sort(counts_array)[-10:]) / total_path_execution_count)
        ninety_percentile_over_total.append(np.percentile(counts_array, 90) / total_path_execution_count)

        total = 0
        for i, n in enumerate(reversed(np.sort(counts_array))):
            total += n
            if total >= (total_path_execution_count * 0.9):
                percent_of_branches_comprising_upper_90percent.append((i+1) / len(counts_array))
                break


    print(f"{variances=}" + "\n"*3)
    print(f"{indices_of_dispersion=}" + "\n"*3)
    print(f"{coefficients_of_variation=}" + "\n"*3)
    print(f"{relative_deviations=}" + "\n"*3)
    print(f"{max_over_total=}" + "\n"*3)


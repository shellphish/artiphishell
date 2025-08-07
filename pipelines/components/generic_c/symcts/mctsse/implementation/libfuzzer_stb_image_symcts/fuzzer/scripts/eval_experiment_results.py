# IPython log file

from collections import defaultdict

import scipy
import scipy.stats
import numpy as np

import pandas as pd


def analyze(results_string):
    s = results_string
    vals = [l.strip().split(',') for l in s.split('\n') if l.strip()]
    res = {}

    res = defaultdict(list)
    for key, val in vals:
        key = '_'.join(key.split('_')[:-1])
        val = int(val)
        res[key] += [val]
    return res

def pick_best_mean(results):
    return

def analyze_data(title, result_string):
    print("# " + title)
    res = analyze(result_string)

    sorted_items = sorted(res.items(), key=lambda key: np.mean(key[1]))
    best_mean_key = sorted_items[-1][0]

    # for key, data in res.items():
    #     print(f"{key}: mean={np.mean(data)} std={np.std(data)} min={np.min(data)} max={np.max(data)}")

    # dataframe containing mean, std, min, max for each key
    df = pd.DataFrame.from_dict({key: [np.mean(data), np.std(data), np.min(data), np.max(data)] for key, data in sorted_items}, orient='index', columns=['mean', 'std', 'min', 'max'])
    print(df)
    print("Best (mean): ", best_mean_key)

    print("## Mann-Whitney U test ##")
    for key, results in sorted(res.items(), key=lambda key: np.mean(key[1])):
        print(f"{best_mean_key} vs {key}: ", scipy.stats.mannwhitneyu(res[best_mean_key], results))

    print('\n')

results_mutations_string = '''
qsym_1,1118
qsym_3,1118
qsym_5,1118
qsym_7,1118
optimistic_5,1121
optimistic_6,1121
optimistic_7,1121
optimistic_8,1121
optimistic_9,1121
quicksampler_path_sensitive_5,2759
quicksampler_6,3002
quicksampler_8,3049
quicksampler_path_sensitive_3,3055
quicksampler_path_sensitive_9,3139
quicksampler_4,3270
qsym_0,3361
all_6,3423
optimistic_3,3482
optimistic_0,3483
all_7,3639
optimistic_1,3683
sage_2,3773
optimistic_4,3877
optimistic_2,4014
quicksampler_path_sensitive_7,4172
qsym_9,4179
quicksampler_path_sensitive_2,4182
quicksampler_path_sensitive_8,4252
sage_9,4274
quicksampler_path_sensitive_1,4303
all_5,4326
quicksampler_1,4330
quicksampler_3,4336
qsym_8,4368
qsym_2,4369
qsym_4,4371
quicksampler_path_sensitive_4,4398
sage_1,4489
quicksampler_7,4516
quicksampler_9,4535
quicksampler_5,4579
quicksampler_path_sensitive_0,4582
quicksampler_0,4585
quicksampler_path_sensitive_6,4604
qsym_6,4634
quicksampler_2,4662
sage_0,5015
sage_6,5115
sage_3,5133
all_2,5134
all_8,5138
sage_4,5208
sage_7,5291
all_9,5336
all_4,5375
all_3,5563
sage_8,5576
all_1,5578
sage_5,5818
all_0,6201
'''
analyze_data("Mutations experiment", results_mutations_string)

results_accept_shorter_string = """
novel_only_4,3540
novel_only_0,3564
novel_only_2,3962
novel_only_1,4181
accept_shorter_8,4976
accept_shorter_9,5069
novel_only_9,5122
accept_shorter_6,5164
accept_shorter_2,5169
novel_only_3,5188
accept_shorter_0,5207
novel_only_6,5276
novel_only_8,5332
accept_shorter_3,5370
accept_shorter_1,5401
accept_shorter_4,5427
novel_only_7,5520
accept_shorter_5,5609
accept_shorter_7,5615
novel_only_5,5618
"""
analyze_data("Feedback experiment", results_accept_shorter_string)

results_string_generational_search = """
generational_0,43847
generational_1,23871
generational_2,38062
generational_3,42776
generational_4,32184
generational_5,44977
generational_6,45694
generational_7,36992
generational_8,53863
generational_9,38999
non_generational_0,30185
non_generational_1,42546
non_generational_2,51248
non_generational_3,36423
non_generational_4,46413
non_generational_5,32836
non_generational_6,28266
non_generational_7,48332
non_generational_8,40169
non_generational_9,43525
"""

analyze_data("Generational search", results_string_generational_search)

results_string_coverage = """
bucketing_symcts_1,3561
bucketing_symcts_5,3735
no_bucketing_5,3740
bucketing_symcts_4,3835
bucketing_afl_5,4249
bucketing_afl_7,4325
bucketing_symcts_context_sensitive_2,4884
bucketing_symcts_2,4938
no_bucketing_7,4945
bucketing_symcts_8,5020
no_bucketing_context_sensitive_6,5045
bucketing_symcts_context_sensitive_5,5055
bucketing_symcts_context_sensitive_6,5119
bucketing_symcts_6,5146
bucketing_symcts_context_sensitive_3,5163
bucketing_symcts_context_sensitive_4,5203
bucketing_afl_6,5209
no_bucketing_context_sensitive_1,5222
bucketing_afl_context_sensitive_1,5255
no_bucketing_context_sensitive_3,5285
no_bucketing_9,5293
no_bucketing_context_sensitive_4,5294
no_bucketing_context_sensitive_7,5294
bucketing_symcts_9,5297
bucketing_afl_2,5303
bucketing_afl_context_sensitive_7,5313
no_bucketing_0,5336
bucketing_symcts_0,5340
bucketing_afl_context_sensitive_8,5348
no_bucketing_4,5378
no_bucketing_8,5387
bucketing_symcts_3,5410
no_bucketing_6,5420
no_bucketing_3,5429
bucketing_afl_4,5453
no_bucketing_1,5529
no_bucketing_2,5548
bucketing_afl_context_sensitive_5,5585
bucketing_afl_context_sensitive_0,5619
bucketing_afl_9,5624
bucketing_symcts_context_sensitive_8,5629
bucketing_afl_0,5686
no_bucketing_context_sensitive_8,5726
bucketing_symcts_7,5727
bucketing_symcts_context_sensitive_9,5742
bucketing_afl_1,5772
no_bucketing_context_sensitive_9,5772
bucketing_afl_context_sensitive_9,5773
no_bucketing_context_sensitive_5,5777
no_bucketing_context_sensitive_0,5801
no_bucketing_context_sensitive_2,5804
bucketing_afl_context_sensitive_4,5855
bucketing_afl_3,5860
bucketing_symcts_context_sensitive_7,5871
bucketing_symcts_context_sensitive_1,5928
bucketing_afl_8,5971
bucketing_afl_context_sensitive_3,5983
bucketing_symcts_context_sensitive_0,5997
bucketing_afl_context_sensitive_2,6050
bucketing_afl_context_sensitive_6,6907
"""
analyze_data("Coverage experiment", results_string_coverage)

results_string_scheduling = """
uniform_random_4,712
uniform_random_8,1297
uniform_random_6,1310
weighted_random_0,1325
weighted_random_8,1369
weighted_random_9,1531
uniform_random_0,1566
weighted_random_4,1594
weighted_random_1,1671
weighted_random_7,1683
weighted_random_2,1805
weighted_random_6,1813
uniform_random_3,1836
uniform_random_1,1848
uniform_random_2,1940
uniform_random_5,1990
uniform_random_9,2017
weighted_random_3,2038
weighted_random_5,2280
uniform_random_7,2455
weighted_minimum_2,3262
weighted_minimum_1,3393
weighted_minimum_4,4526
weighted_minimum_3,4810
weighted_minimum_0,5049
weighted_minimum_5,5299
weighted_minimum_8,5479
weighted_minimum_9,5540
weighted_minimum_6,5648
weighted_minimum_7,5813
"""
analyze_data("Scheduling", results_string_scheduling)
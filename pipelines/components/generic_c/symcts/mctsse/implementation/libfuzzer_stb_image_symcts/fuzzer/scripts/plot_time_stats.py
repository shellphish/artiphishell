import sys
import pandas as pd
import matplotlib.pyplot as plt

with open(sys.argv[1], 'r') as f:
    # read time_stats.tsv
    # columns: time_solved, time_traced, num_inputs_total, num_inputs_unique
    df = pd.read_csv(f, sep='\t', header=None, names=['time_solved', 'time_traced', 'num_inputs_total', 'num_inputs_unique'], index_col=False)

    df['time_solved_accum'] = df['time_solved'].cumsum()
    df['time_traced_accum'] = df['time_traced'].cumsum()

    # calculate the moving average with timestep 5 of the time_solved and time_traced columns
    df['time_solved_ma'] = df['time_solved'].rolling(window=5).mean()
    df['time_traced_ma'] = df['time_traced'].rolling(window=5).mean()

    # calculate time_solved/num_inputs_unique and time_traced/num_inputs_unique over the accumulated steps so far
    df['time_solved_per_input'] = df['time_solved_accum'] / df['num_inputs_unique']
    df['time_traced_per_input'] = df['time_traced_accum'] / df['num_inputs_unique']

    # each row is the stats for one iteration

    # plot time_solved and time_traced per iteration
    # plot num_inputs_total and num_inputs_unique per iteration on a log scale


    # df.plot(y=['time_solved', 'time_traced'], title='Time per iteration', logy=False)
    # plt.show()

    # now plot the moving averages
    df.plot(y=['time_solved_ma', 'time_traced_ma'], title='Time per iteration', logy=False)
    plt.show()

    # # plot time_solved/num_inputs_unique and time_traced/num_inputs_unique
    # df.plot(y=['time_solved_per_input', 'time_traced_per_input'], title='Time per input', logy=False)
    # plt.show()

    # plot time_solved_accum and time_traced_accum
    df.plot(y=['time_solved_accum', 'time_traced_accum'], title='Time accumulated', logy=False)
    plt.show()
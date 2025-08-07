import os

def parse_table(s):
    lines = [s for s in s.strip().split('\n') if s.strip()]
    return [l.split() for l in lines]

    # res = []
    # for line in lines:
    #     vals = []
    #     for val in line.split():
    #         try:
    #             val = int(val)
    #         except:
    #             try:
    #                 val = float(val)
    #             except:
    #                 pass

    #         vals.append(val)

    #     res.append(vals)

    # return res

def format_markdown_table(res):
    s = ''
    for i, row in enumerate(res):
        fuzzer,last_reported, count, min, max, mean, median = row

        s += f'| {fuzzer:18} | {last_reported:18} | {count:6} | {min:5} | {max:5} | {mean:13} | {median:10} |\n'
        if i == 0:
            s += '| ------------------ | ------------------ | ------ | ----- | ----- | ------------- | ---------- |\n'
    return s

def format_latex_table(res):
    s = '''
\\begin{table*}[h]
\\centering
\\begin{tabular}{|l|l|l|l|l|l|l|}
\\hline
\\textbf{Fuzzer} & \\textbf{Last Reported} & \\textbf{Count} & \\textbf{Min} & \\textbf{Max} & \\textbf{Mean} & \\textbf{Median} \\\\
\\hline
'''
    for i, row in enumerate(res[1:]):
        fuzzer,last_reported, count, min, max, mean, median = row
        fuzzer = fuzzer.replace('_', '\\_')

        s += f'{fuzzer:18} & {last_reported:18} & {count:6} & {min:5} & {max:5} & {mean:13} & {median:10} \\\\\n'
    s += '\\hline\n'
    s += '\\end{tabular}\n\\end{table*}'
    return s

dirs = ['fuzzbench/tables/2d', 'fuzzbench/tables/4d', 'magma/tables/']

for _dir in dirs:
    table_names = [f[:-4] for f in os.listdir(_dir) if f.endswith('.txt')]
    for name in table_names:
        with open(f'{_dir}/{name}.txt', 'r') as f:
            text = f.read()
        with open(f'{_dir}/{name}.md', 'w') as f:
            f.write(format_markdown_table(parse_table(text)))
        with open(f'{_dir}/{name}.tex', 'w') as f:
            f.write(format_latex_table(parse_table(text)))
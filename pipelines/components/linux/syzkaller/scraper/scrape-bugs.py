import os
import time
import pathlib
import requests
import subprocess
from bs4 import BeautifulSoup
import json
import multiprocessing
from collections import defaultdict

import clang.cindex

clang.cindex.Config.set_library_file('/usr/lib/llvm-12/lib/libclang-12.so.1')

GET_REPROS = False
CHECKOUT_LINUX = False
GET_URLS = False
GET_STATS = True
COLLECT_DATASET = True
ADD_CWD = False
CHANGED_FUNCS = False
ADD_CWE = False
GET_FUNCSOURCE = True


with open("bugs.json", "r") as f:
    bugs_json = json.loads(f.read())

base_url = "https://syzkaller.appspot.com"

def createdir(name):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    os.makedirs(d, exist_ok=True)
    return d

def is_patch_link(tag):
    return (tag.name == "span" and tag.previous_sibling and
            tag.previous_sibling.previous_sibling and
            tag.previous_sibling.previous_sibling.name == "b" and
            tag.previous_sibling.previous_sibling.text.strip() == "Fix commit:")

def checkout_linux():
    print("[*] checking out linux... ", end="")
    os.system("git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/")

def cleanup_linux():
    os.system("rm -rf linux")

def find_source_files(diff):
    files = []
    for line in diff.split("\n"):
        if line.startswith("+++"):
            files.append(line[6:])
    return files

def get_code(fpath, start, end):
    start -= 1
    end -= 1
    code = ''
    with open(fpath) as f:
        for i, line in enumerate(f):
            if start <= i <= end:
                code += line
            if i == end:
                break
    return code

SUFFIX = ['.cpp', '.c', '.h', '.hpp']

def get_function_source_code(r):
    # first, find the relevant source files
    if 'fix_commit_diff' not in repros[r]:
        return repros[r]
    if not 'changed_funcs' in repros[r]:
        return repros[r]
    fpaths = find_source_files(repros[r]['fix_commit_diff'])

    seen_func = set()

    for fpath in fpaths:
        if not any(fpath.endswith(s) for s in SUFFIX):
            print(f"[!] Cannot handle {fpath}")
            continue

        tag = repros[r]['fix_commit_hash'] + ":" + fpath
        ending = fpath.split(".")[-1]
        myid = multiprocessing.current_process().pid
        fname = f"myout{myid}.{ending}"
        p = subprocess.Popen(f"git show {tag} > {fname}", cwd=repros[r]['cwd'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if p.returncode != 0 and p.returncode is not None:
            print(f"[!] Could not cat {repros[r]['fix_commit_hash']} in {repros[r]['cwd']}{p.returncode}")
            print("===============")
            print(p.stderr.read().decode("utf-8"))
            print("===============")
            print(p.stdout.read().decode("utf-8"))
            print("===============")
            pathlib.Path(os.path.join(repros[r]['cwd'], fname)).unlink(missing_ok=True)
            continue


        index = clang.cindex.Index.create()
        print(f"[*] parsing {fpath}... ")
        try:
            tu = index.parse(os.path.join(repros[r]['cwd'], fname), args=['-fparse-all-comments'],
                             options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        except Exception as e:
            print(f"[!] Could not parse {fpath}")
            #print(e)
            pathlib.Path(os.path.join(repros[r]['cwd'], fname)).unlink(missing_ok=True)
            continue
        print(f"[*] done parsing {fpath}")
        #import ipdb; ipdb.set_trace()
        for c in tu.cursor.walk_preorder():
            file = c.extent.start.file
            if not file or not fpath in file.name:
                continue

            # we don't care about function declarations
            if not c.is_definition():
                continue

            # TODO in ipython, load block/blk-map.c, look for bio_copy_user_iov and see why we don't find it
            # we only care about function/method definitions
            ck = clang.cindex.CursorKind
            if c.kind not in [ck.FUNCTION_DECL, ck.CXX_METHOD, ck.FUNCTION_TEMPLATE]:#, ck.DESTRUCTOR, ck.CONSTRUCTOR]:
                continue

            func_name = c.spelling
            if func_name in seen_func:
                print("[!] We've seen this func name before O.o")
                continue

            if not func_name in repros[r]['changed_funcs']:
                continue

            seen_func.add(func_name)
            start_line = c.extent.start.line
            end_line = c.extent.end.line
            code = get_code(os.path.join(repros[r]['cwd'], fpath), start_line, end_line)
            if 'source_code' not in repros[r]:
                repros[r]['source_code'] = {}
            repros[r]['source_code'][func_name] = code
        pathlib.Path(os.path.join(repros[r]['cwd'], fname)).unlink(missing_ok=True)
    if not 'source_code' in repros[r]:
        if len(repros[r]['changed_funcs']) > 0:
            print(f"[!] source code not found for {repros[r]['changed_funcs']}")
    else:
        for func in repros[r]['changed_funcs']:
            if func not in repros[r]['source_code']:
                print(f"[!] {func} not found in source code")
    return repros[r]

str_2_cwe = {
    'out-of-bounds Read': 'CWE-125',
    'out-of-bounds Write': 'CWE-787',
    'use-after-free': 'CWE-416',
    'NULL pointer dereference': 'CWE-476',
}

def find_cwe(repros):
    print("[*] finding CWEs... ", end="")
    for r in repros:
        for key in str_2_cwe:
            if key in r:
                repros[r]['cwe'] = str_2_cwe[key]
                break
        if not 'cwe' in repros[r]:
            repros[r]['cwe'] = "UNKNOWN"
    print("done")

def get_changed_functions(r):
    if 'cwd' not in repros[r]:
        return repros[r]
    if 'fix_commit_hash' not in repros[r]:
        if 'fix_commit_url' in repros[r]:
            repros[r]['fix_commit_hash'] = repros[r]['fix_commit_url'].split("=")[-1]
        else:
            p = subprocess.Popen(f"git log --format=oneline | grep \"{repros[r]['fix_commit_title']}\"",
                                 cwd=repros[r]['cwd'], shell=True, stdout=subprocess.PIPE)
            repros[r]['fix_commit_hash'] = p.stdout.read().decode("utf-8").strip().split(" ")[0]

        #return repros[r]
    p = subprocess.Popen((f"git diff {repros[r]['fix_commit_hash']}~ {repros[r]['fix_commit_hash']} | "
                          + "grep -E '^(@@)' | grep \"(\" | sed 's/@@.*@@//' | sed 's/(.*//'"
                          + " | awk -F \" \" '{print $NF}' | uniq"),
                         cwd=repros[r]['cwd'], shell=True, stdout=subprocess.PIPE)
    #p = subprocess.Popen(["git", "diff", repro['fix_commit_hash']+"~", repro['fix_commit_hash']],
    #                     cwd="linux", stdout=subprocess.PIPE)
    diff = p.stdout.read().decode("utf-8")
    diff = diff.split("\n")
    funcs = [line for line in diff if len(line) > 0]
    funcs = [line[1:] if line[0] == "*" else line for line in funcs]
    repros[r]['changed_funcs'] = funcs
    return repros[r]

def collect_repros(repros):
    print("[*] collecting syz-repros... ", end="")
    for r in repros:
        done = False
        while not done:
            syzrep = requests.get(repros[r]['syz'])
            if syzrep.content == b'429 Too Many Requests\nPlease contact us at syzkaller@googlegroups.com if you need access to our data.\n' :
                print(f"[*] syzbot complained, sleeping for 60s (at {count})")
                time.sleep(60)
            else:
                done = True
        #syzrep = requests.get(repros[r]['syz'])
        sp = syzrep.text.split("\n")
        out = [line for line in sp if len(line) > 0 and line[0] != "#"]
        out = "\n".join(out)
        with open(os.path.join(repro_dir, "repro_" + str(repros[r]['id'])), "w") as f:
            f.write(out)
    print("done")

def add_cwd(r):
    if 'fix_commit_url' in repros[r]:
        repros[r]['cwd'] = "linux"
    else:
        p = subprocess.Popen(f"git log --format=oneline | grep \"{repros[r]['fix_commit_title']}\"",
                             cwd="bpf-next", shell=True, stdout=subprocess.PIPE)
        commit_hash = p.stdout.read().decode("utf-8").strip().split(" ")[0]
        if commit_hash == "":
            p = subprocess.Popen(f"git log --format=oneline | grep \"{repros[r]['fix_commit_title']}\"",
                                 cwd="linux", shell=True, stdout=subprocess.PIPE)
            commit_hash = p.stdout.read().decode("utf-8").strip().split(" ")[0]
            if commit_hash != "":
                repros[r]['cwd'] = "linux"
        else:
            repros[r]['cwd'] = "bpf-next"
    return repros[r]


def get_stats(repros):
    print("[*] collecting stats... ")
    mainline = 0
    other = 0
    cwes = defaultdict(int)
    sources = 0
    changed_funcs = 0
    for r in repros:
        if 'fix_commit_url' in repros[r]:
            mainline += 1
        else:
            other += 1
        if 'cwe' in repros[r]:
            cwes[repros[r]['cwe']] += 1
        if 'source_code' in repros[r]:
            sources += 1
        if 'changed_funcs' in repros[r]:
            changed_funcs += 1
    print(f"[*] mainline: {mainline}, other: {other}")
    print(f"[*] CWEs: {cwes}")
    print(f"[*] source code: {sources}")
    print(f"[*] changed functions: {changed_funcs}")


def collect_one_report(r):
    if os.path.exists(os.path.join(repro_dir, "repro_" + str(repros[r]['id']) + ".json")):
        with open(os.path.join(repro_dir, "repro_" + str(repros[r]['id']) + ".json"), "r") as f:
            return json.loads(f.read())
    json_out = {}
    json_out['syz'] = repros[r]['syz']
    json_out['c'] = repros[r]['c']
    json_out['config'] = repros[r]['config']
    json_out['report_url'] = repros[r]['report']
    json_out['id'] = repros[r]['id']

    done = False
    while not done:
        report = requests.get(repros[r]['report'])
        if report.content == b'429 Too Many Requests\nPlease contact us at syzkaller@googlegroups.com if you need access to our data.\n' :
            #print(f"[*] syzbot complained, sleeping for 60s (at {count})")
            print("[*] syzbot complained, sleeping for 60s")
            time.sleep(60)
        else:
            done = True
    #syzrep = requests.get(repros[r]['syz'])
    json_out['report_content'] = report.text

    # collect patching commit
    commit_hash = ""
    cwd = "linux"
    if 'fix_commit_url' in repros[r]:
        # this assumes that the link has only one parameter that specifies the commit hash
        commit_hash = repros[r]['fix_commit_url'].split("=")[-1]
        json_out['fix_commit_url'] = repros[r]['fix_commit_url']
        json_out['fix_commit_hash'] = commit_hash

    elif 'fix_commit_title' in repros[r]:
        p = subprocess.Popen(f"git log --format=oneline | grep \"{repros[r]['fix_commit_title']}\"",
                             cwd=cwd, shell=True, stdout=subprocess.PIPE)
        commit_hash = p.stdout.read().decode("utf-8").strip().split(" ")[0]
        #p = subprocess.Popen(["git", "log", "--format=%H", "--grep", repros[r]['fix_commit_title']],
        #                     cwd="linux", stdout=subprocess.PIPE)
        #commit_hash = p.stdout.read().decode("utf-8").strip()
        json_out['fix_commit_title'] = repros[r]['fix_commit_title']
        if commit_hash == "":
            cwd = "bpf-next"
            p = subprocess.Popen(f"git log --format=oneline | grep \"{repros[r]['fix_commit_title']}\"",
                                 cwd=cwd, shell=True, stdout=subprocess.PIPE)
            commit_hash = p.stdout.read().decode("utf-8").strip().split(" ")[0]
        json_out['fix_commit_hash'] = commit_hash
    if commit_hash == "":
        print(f"[*] no fix commit for {r}")
        #count += 1
        with open(os.path.join(repro_dir, "repro_" + str(repros[r]['id']) + ".json"), "w") as f:
            f.write(json.dumps(json_out, indent=4))
        return json_out
    p = subprocess.Popen(["git", "log", "--format=%B", "-n", "1", commit_hash],
                         cwd=cwd, stdout=subprocess.PIPE)
    json_out['fix_commit_desc'] = p.stdout.read().decode("utf-8")
    p = subprocess.Popen(["git", "diff", commit_hash+"~", commit_hash], cwd=cwd, stdout=subprocess.PIPE)
    json_out['fix_commit_diff'] = p.stdout.read().decode("utf-8")
    json_out['cwd'] = cwd
    #count += 1
    with open(os.path.join(repro_dir, "repro_" + str(repros[r]['id']) + ".json"), "w") as f:
        f.write(json.dumps(json_out, indent=4))
    print("[*] finished ", repros[r]['id'])
    return json_out

def collect_dataset(repros):
    print("[*] collecting dataset... ")
    if os.path.exists(os.path.join(repro_dir, "repros.json")):
        print("[*] repros.json exists, loading... ")
        with open(os.path.join(repro_dir, "repros.json"), "r") as f:
            repros = json.loads(f.read())
    else:
        p = subprocess.run(["git", "config", "diff.renameLimit", "999999"], cwd="linux")
        count = 0
        with multiprocessing.Pool() as pool:
            for result in pool.map(collect_one_report, repros):
                for r in repros:
                    if repros[r]['id'] == result['id']:
                        repros[r] = result
                #repros[result["id"]] = result
        with open(os.path.join(repro_dir, "repros.json"), "w") as f:
            f.write(json.dumps(repros, indent=4))
        """
        for r in repros:
            # collect crash report
            collect_one_report(r)
        """
        print("[*] done")
    return repros


repro_dir = createdir("repros")

repros = {}

def collect_urls(repros):
    print("[*] collecting urls... ")
    count = 0
    for bug in bugs_json:
        done = False
        while not done:
            response = requests.get(bugs_json[bug])
            if response.content == b'429 Too Many Requests\nPlease contact us at syzkaller@googlegroups.com if you need access to our data.\n' :
                print(f"[*] syzbot complained, sleeping for 60s (at {count})")
                time.sleep(60)
            else:
                done = True
        soup = BeautifulSoup(response.content, "html.parser")
        tables = soup.find_all("table",class_="list_table")
        if len(tables) == 0:
            #import ipdb; ipdb.set_trace()
            continue
        table = tables[-1]
        table_rows = table.find_all("tr")
        # pop the header
        table_rows.pop(0)
        for row in table_rows:
            if (row.find_all("td",class_="repro")[2].text == ""
                and row.find_all("td",class_="repro")[3].text == ""):
                continue

            report_url = base_url + row.find_all("td", class_="repro")[2].find("a").get("href")

            syz_repro_url = base_url + row.find_all("td", class_="repro")[2].find("a").get("href")
            c_repro_url = ""
            if not row.find_all("td",class_="repro")[3].text == "":
                c_repro_url = base_url + row.find_all("td", class_="repro")[3].find("a").get("href")
            config_url = base_url + row.find("td",class_="config").find("a").get("href")

            repros[bug] = {}
            repros[bug]['config'] = config_url
            repros[bug]['syz'] = syz_repro_url
            repros[bug]['c'] = c_repro_url
            repros[bug]['id'] = count
            repros[bug]['report'] = report_url
            count += 1
            break
        #import ipdb; ipdb.set_trace()
        span = soup.find(is_patch_link)
        if span:
            if span.find("a"):
                repros[bug]['fix_commit_url'] = span.find("a").get("href")
            else:
                repros[bug]['fix_commit_title'] = span.text.strip()
        else:
            print("No patch for", bug)
            print(bugs_json[bug])

    print("[*] collection done")
    with open("repros.json", "w") as f:
        f.write(json.dumps(repros, indent=4))

def load_urls():
    with open("repros.json", "r") as f:
        repros = json.loads(f.read())
    return repros


if GET_URLS:
    collect_urls(repros)
else:
    repros = load_urls()


if GET_REPROS:
    collect_repros(repros)

if CHECKOUT_LINUX:
    checkout_linux()

if COLLECT_DATASET:
    repros = collect_dataset(repros)

if ADD_CWD:
    print("[*] adding cwd... ", end="")
    with multiprocessing.Pool(processes=24) as pool:
        for result in pool.map(add_cwd, repros):
            for r in repros:
                if repros[r]['id'] == result['id']:
                    repros[r] = result
    print("done")
    #for r in repros:
    #    add_cwd(repros[r])

if CHANGED_FUNCS:
    print("[*] adding changed functions... ", end="")
    with multiprocessing.Pool(processes=24) as pool:
        for result in pool.map(get_changed_functions, repros):
            for r in repros:
                if repros[r]['id'] == result['id']:
                    repros[r] = result
    #for r in repros:
    #    repros[r]['changed_funcs'] = get_changed_functions(repros[r])
    print("done")

if ADD_CWE:
    print("[*] adding CWEs... ", end="")
    find_cwe(repros)
    print("done")

if GET_FUNCSOURCE:
    print("[*] getting function source code... ", end="")
    #for r in repros:
    #   repros[r] = get_function_source_code(r)
    with multiprocessing.Pool(processes=24) as pool:
        for result in pool.map(get_function_source_code, repros):
            for r in repros:
                if repros[r]['id'] == result['id']:
                    repros[r] = result
    print("done")

if GET_STATS:
    get_stats(repros)

if CHECKOUT_LINUX:
    cleanup_linux()

with open(os.path.join(repro_dir, "repros.json"), "w") as f:
    f.write(json.dumps(repros, indent=4))

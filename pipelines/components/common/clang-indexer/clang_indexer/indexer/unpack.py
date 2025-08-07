import os
import sys
import json
import random
import string

import sqlite3

def rand_str(N):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

def is_unique(cur, table, col, name):
    res = cur.execute(f"SELECT * FROM {table} WHERE {col} == '{name}';")
    records = res.fetchall()
    return len(records) == 1

def unpack(db_path, dst_path):
    assert os.path.exists(db_path)
    assert not os.path.exists(dst_path)

    con = sqlite3.connect(db_path)

    cur = con.cursor()
    res = cur.execute("SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
    tables = [x[0] for x in res.fetchall()]

    for table in tables:
        print(table)
        res = cur.execute(f"select name from pragma_table_info('{table}') as tblInfo;")
        table_path = os.path.join(dst_path, table)
        os.system(f"mkdir -p {table_path}")
        legend = [x[0] for x in res.fetchall()]

        res = cur.execute(f"SELECT * FROM {table};")
        records = res.fetchall()
        assert len(legend) == len(records[0])
        for record in records:
            content = {legend[i]:record[i] for i in range(len(legend))}
            # decide file name, prefer to use function name as the file name, but if it is not unique
            # give it a random suffix
            name =  content['full_name'] if table == 'method_info' else content['name']
            if not is_unique(cur, table, 'full_name' if table == 'method_info' else 'name', name):
                name += "__"+rand_str(4)

            record_path = os.path.join(table_path, name) + '.json'
            with open(record_path, 'w') as f:
                json.dump(content, f, indent=4)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("db", type=str, help="source code directory")
    parser.add_argument("-o", "--output", type=str, default="unpacked", help="output directory (default: unpacked)")
    args = parser.parse_args()

    assert args.db.endswith('.db')
    unpack(args.db, args.output)

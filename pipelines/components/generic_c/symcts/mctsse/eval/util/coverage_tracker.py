import sys
import json
import time
import struct
import contextlib
from multiprocessing.shared_memory import SharedMemory

NUM_INTS = 0x1000
SIZE = NUM_INTS * 8
run_name = sys.argv[1]
names = sys.argv[2:]
assert names
def every_interval(interval):
    current = time.time()
    while True:
        yield current
        time.sleep(max(current + interval - time.time(), 0))
        current += interval

@contextlib.contextmanager
def shared_memory_mappings(names):
    coverage_mappings = {
        name: SharedMemory(name=f'/{name}', create=True, size=SIZE) for name in names
    }
    try:
        yield coverage_mappings
    finally:
        for shm in coverage_mappings.values():
            shm.close()
            shm.unlink()

def percentages(counts):
    return [(counts[i] / (counts[i+1]+counts[i]) if counts[i+1]+counts[i] else counts[i]) for i in range(0, len(counts), 2)]
with shared_memory_mappings(names) as mappings:
    with open(f"counts_{run_name}.json", 'w') as f:
        f.write(json.dumps(names) + '\n')
        prev_cum_counts = {name: [0] * NUM_INTS for name in names}
        for ts in every_interval(30):
            tick_counts, cum_counts = {}, {}
            tick_percents, cum_percents = {}, {}
            for name, shm in mappings.items():
                cur = bytes(shm.buf[:SIZE])
                print(ts, name, cur[:0x40])
                counts = struct.unpack("<" + 'Q' * NUM_INTS, cur)
                tick_counts[name] = counts
                cum_counts[name] = [counts[i] + prev_cum_counts[name][i] for i in range(NUM_INTS)]
                prev_cum_counts[name] = cum_counts[name]

                tick_percents[name] = percentages(counts)
                cum_percents[name] = percentages(cum_counts[name])
                print(cum_percents[name][:100])
                shm.buf[:SIZE] = bytes([0] * SIZE)
            print()
            f.write(json.dumps(dict(
                tick=ts,
                tick_counts=tick_counts,
                cumulative_counts=cum_counts,
                tick_percents=tick_percents,
                cumulative_percents=cum_percents
            )) + '\n')
            f.flush()

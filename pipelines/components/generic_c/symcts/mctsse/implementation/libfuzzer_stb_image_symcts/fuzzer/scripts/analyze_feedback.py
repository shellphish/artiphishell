

from pathlib import Path
import sys


def parse_feedback_log(sync_dir):
    """Analyze feedback metric log."""

    with open(sync_dir / '.feedback.log') as f:
        lines = f.read().strip().split('\n')
        log = []
        for line in lines:
            timestamp, edge, _, count, *reason = line.split()
            count = int(count)
            edge = int(edge, base=0)
            timestamp = int(timestamp)
            log.append((timestamp, edge, count))
    return log

def first_discovery_of_edges(log):
    """Find the first time each edge was discovered."""

    first_discovery = {}
    for timestamp, edge, count in log:
        count = 1 if count > 0 else 0
        if (edge, count) not in first_discovery:
            first_discovery[(edge, count)] = timestamp
    return list(sorted([(timestamp, (edge, count)) for (edge, count), timestamp in first_discovery.items()]))

print(first_discovery_of_edges(parse_feedback_log(Path(sys.argv[1]))))
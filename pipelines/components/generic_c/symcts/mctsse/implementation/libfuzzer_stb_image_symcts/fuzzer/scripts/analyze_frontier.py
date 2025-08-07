

# load final metadata json
import json
import sys


with open(sys.argv[1]) as f:
    metadata = json.load(f)

edges_seen = set()
edges_hit = set()
for edge, data in metadata.items():
    edge_id, count = edge.split(' * ')
    edges_seen.add(edge_id)
    if int(count) > 0:
        edges_hit.add(edge_id)

assert edges_hit.issubset(edges_seen)

edges_not_hit = edges_seen.difference(edges_hit)

print(f"Edges seen: {len(edges_seen)}")
print(f"Edges hit: {len(edges_hit)}")
print(f"Unreached frontier edges: {len(edges_not_hit)}")

print(f"Edges hit:     {list(sorted(edges_hit))}")
print(f"Edges not hit: {list(sorted(edges_not_hit))}")


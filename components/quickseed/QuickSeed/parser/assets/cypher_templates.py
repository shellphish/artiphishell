ALL_SHORTEST_PATHS_TEMPLATE = """
    MATCH (start:CFGFunction), (end: CFGFunction) 
    WHERE start.identifier CONTAINS $source_identifier
    AND end.identifier CONTAINS $target_identifier
    WITH start, end 
    MATCH path = allShortestPaths((start)-[:DIRECTLY_CALLS*1..{{ max_depth|default(10) }}]->(end)) 
    RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""


SHORTEST_PATH_TEMPLATE = """
    MATCH (start:CFGFunction), (end: CFGFunction) 
    WHERE start.identifier CONTAINS $source_identifier
    AND end.identifier CONTAINS $target_identifier
    WITH start, end 
    MATCH path = shortestPath((start)-[:DIRECTLY_CALLS*1..{{ max_depth|default(10) }}]->(end)) 
    RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""


# Alternative: Separate queries if you want more detailed information
CALLERS_TEMPLATE = """
    MATCH (caller: CFGFunction)-[:DIRECTLY_CALLS]->(target:CFGFunction)
    WHERE target.identifier = "{{ target_identifier }}"
    RETURN caller.identifier as caller_identifier,
           target.identifier as target_identifier;
"""

CALLEES_TEMPLATE = """
    MATCH (target:CFGFunction)-[:DIRECTLY_CALLS]->(callee: CFGFunction)
    WHERE target.identifier = "{{ target_identifier }}"
    RETURN target.identifier as target_identifier,
           callee.identifier as callee_identifier;
"""

ALL_PATHS_ENDING_AT_TEMPLATE = """
MATCH (end:CFGFunction)
WHERE end.identifier CONTAINS $target_identifier
CALL apoc.path.expandConfig(end, {
    relationshipFilter: "<DIRECTLY_CALLS",
    minLevel: 1,
    maxLevel: {{ max_depth|default(10) }}
}) YIELD path
RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""

# We should only query one source, one sink at a time for efficiency
ALL_PATHS_TEMPLATE = """
MATCH (start:CFGFunction), (end:CFGFunction)
WHERE start.identifier CONTAINS $start_identifier
AND end.identifier CONTAINS $target_identifier
MATCH path = (start)-[:DIRECTLY_CALLS*1..{{ max_depth|default(10) }}]->(end)
RETURN DISTINCT path {% if limit %}LIMIT {{ limit }}{% endif %};
"""
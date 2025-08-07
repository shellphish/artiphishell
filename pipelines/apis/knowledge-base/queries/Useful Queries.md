#
# Security-Advisory-adjacent commits that build correctly

Return all commits that are linked to a security advisory and build correctly.
Additionally, return the CVEs and References that are linked to the advisory, if known.

```cypher
MATCH (n:JenkinsAdvisory)-->(c:Commit)
OPTIONAL MATCH (cve:CVE)-->(ref:Reference)-->(n)
WHERE c.successfully_built
RETURN cve, ref, n, c
```

# JenkinsCore security advisories

Return all advisories which are referenced by CVEs that refer to a non-plugin Jenkins Product.
Additionally, return any referenced commits (e.g. fixed and vulnerable commits) if they are known.

## Full Version
```cypher
MATCH (prod:JenkinsCore)<--(cve:CVE)-->(ref:Reference)-->(n:JenkinsAdvisory)
OPTIONAL MATCH (n)-->(c:Commit)
RETURN prod cve, ref, n, c
```

## Minimal Version (for r3x)
```cypher
MATCH (prod:JenkinsCore)<--(cve:CVE)-->(ref:Reference)-->(n:JenkinsAdvisory)
OPTIONAL MATCH (n)-->(c:Commit)
RETURN n, c
```
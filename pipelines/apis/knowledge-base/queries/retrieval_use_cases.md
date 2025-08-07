Given a presumably vulnerable code, find the closest CVE (before the patch) and retrieve the code after the patch.
 - Assumption: Target vulnerabilities are inspired by real CVEs so we should be able to find the "most similar CVE" to our vulnerability.
 - instead of going from vulnerable -> patch, within the code base, similar functionality without vulnerability/used correctly, use that to patch ours?

Go from an issue report (syzkaller crash) find issues in the mailing list that have similar reports, grab discussions, grab patches, test cases, patch reports
Match report to report-discussion (e.g., I have an ASAN report, find me issues that have similar looking ASAN reports)


Can we find similar issues that crash in similar places in the code? Find existing CVEs that have similar vulnerable code locations.

Instead of going from location, start from existing CVEs, find the closest ones (e.g., new vuln. is a copy paste from an existing one into a new place/new context).

Start from a syzkaller crash (connected to harnesses) -> Find the closest/most similar syzkaller crashes among known -> map known syzkaller program to C reproducer -> use that to produce our own C reproducer for our own crash (ChatGPT <3 <3)

We find a bug in a specific location (sqlinjection in function X) -> find most similar code in our code base -> ask LLM if the bug is present in these other locations too -> find variants of the same bug

Ask LLM to describe the vulnerabiity (security concern) and match from known vulnerability descriptions
- match using the discussion take that and map it back to existing pieces of code the discussion was about, give this info to LLM auditer vulnerabilities that you claimed that exist looked like this in the past, refine your output/give us the vulnerability location/find other vulnerabilities

From the new functionality added, find similar funcs. 
- that exist in other places in the Linux kernel
-in the forks of the Linux kernel 
- other kernel implementations; from that, help us
- retrieve similar interactions
- issues in these implementations (we know what to look for)
- clients (syzklang - reproducers) that use that functionality
- patches if there are known vulnearbilities with the similar functionality


Start with code -> find the change history of similar code -> some of which might be security-related patches -> can we apply that to our code?


throw all existing kernel drivers to KB -> if they added driver to target code, find the most similar driver -> find:
- syzlang descr., real-world bugs, patches, seeds for syzkaller, codeql queries if they already have them
- find codeql queries specific to the code similar to our query


function behavior classification -> based on the description, these are the bugs auditor should be looking for


manually crafted sinks -> embed these sinks -> are there existing bugs happened in functions in these sinks? can we find their patches and use those for our code?

Root causing -> crawl blog post, kernel mailing list -- we have crash -> find similar crashes -> retrieve similar crashes from mailing list/blog posts


Add embeddings for commits - diffs - commit message etc.
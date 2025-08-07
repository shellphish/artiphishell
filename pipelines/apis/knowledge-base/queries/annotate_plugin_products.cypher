MATCH (n:Product)
WHERE
 (n.product =~ '.*Plugin.*' or n.product =~ '.*plugin.*' or n.product =~ '.*plug-in.*' or n.product =~ '.*Plug-in.*')
SET n:JenkinsPlugin
RETURN n;

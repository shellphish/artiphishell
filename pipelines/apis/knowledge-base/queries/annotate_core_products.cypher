MATCH (n:Product)
WHERE
  not (n:JenkinsPlugin)
SET n:JenkinsCore
RETURN n;
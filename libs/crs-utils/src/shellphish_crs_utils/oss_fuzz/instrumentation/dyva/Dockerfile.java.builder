ARG BASE_IMAGE=
FROM ${BASE_IMAGE}

# debug symbols for maven projects
ENV MAVEN_OPTS="-Dmaven.compiler.debug=true -Dmaven.compiler.debuglevel=source,lines,vars"

# debug symbols for gradle projects
ENV GRADLE_OPTS="-Dorg.gradle.java.compile.options.debuggable=true"

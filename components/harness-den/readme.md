## How to...

## 1. Setup Target
### Target 1:
`Apacke Tika`: https://github.com/apache/tika/

#### Build Target
```bash
./build_target.sh -n 1 -j 20 -p tika-parsers
```

`-n`: Predefined commit ID (1-4) [required]

`-j`: Number of threads for parallel build

`-c`: Specific commit hash

`-p`: to build a part of project (refer Tika readme to find your sub module). It is recommened to build only the sub-module you need, else building will take a long time. 

Target build artifacts (jars) will be saved to `/tmp/build_harness/target_build`
Sample fuzzing harness is in ``
(update this Fuzz.java to write your own harness)


#### About Tika
- https://www.baeldung.com/apache-tika

- https://tika.apache.org/3.0.0-BETA2/examples.html

- https://vaadin.com/blog/open-any-file-with-apache-tika

- https://tika.apache.org/1.4/gettingstarted.html


## 2. Setup Jazzer (Fuzzer)

```bash
git clone git@github.com:shellphish-support-syndicate/aixcc-sc-jazzer-examples.git
cd aixcc-sc-jazzer-example
mvn package
```

#### Check if Jazzer is working
```bash
./bin/jazzer --cp=target/jazzer-examples-1.0.0-SNAPSHOT.jar --target_class=com.aixcc.jazzer.examples.CommandInjectionExample
```

Expected output
```
== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executing OS commands with attacker-controlled data can lead to remote code execution.
Found in argument 0
        at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.ProcessImplStartHook(OsCommandInjection.java:35)
        at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1110)
        at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)
        at com.aixcc.jazzer.examples.CommandInjectionExample.fuzzerTestOneInput(CommandInjectionExample.java:28)
DEDUP_TOKEN: 6f2198d292145f8c
== libFuzzer crashing input ==
MS: 0 ; base unit: 0000000000000000000000000000000000000000


artifact_prefix='./'; Test unit written to ./crash-da39a3ee5e6b4b0d3255bfef95601890afd80709
Base64:
reproducer_path='.'; Java reproducer written to ./Crash_da39a3ee5e6b4b0d3255bfef95601890afd80709.java
```


## 3. Start Fuzzing the Target

```bash
cd /tmp/build_harness/tika-fuzz
path_to_jazzer/jazzer \
        --cp=build/libs/tika-fuzz-all.jar \
        --instrumentation_excludes=org.apache.logging.**:org.slf4j.**:com.microsoft.schemas.**:org.openxmlformats schemas.**:org.apache.xmlbeans.**:com.google.protobuf.**:com.google.common.**:ucar.nc2.**:org.mozilla.universalchardet.**:org.jdom2.**:javax.activation.**:javax.xml.bind.**:com.sun.** \
        --target_class=org.dstadler.tika.fuzz.Fuzz \
        -rss_limit_mb=8192
```

if you are in dev container use this

```bash
/classpath/jazzer/jazzer \
        --cp=build/libs/tika-fuzz-all.jar \
        --target_class=org.dstadler.tika.fuzz.Fuzz \
        -rss_limit_mb=8192 \
        --agent_path=/classpath/jazzer/jazzer_standalone_deploy.jar
```

`build/libs/tika-fuzz-all.jar`: jar created for your project submodule and Fuzz.java

Run `build_target.sh` again after you make any code changes to rebuild the project or harness

You can use the exisiting harness in `/tmp/build_harness/tika-fuzz/src/main/java/org/dstadler/tika/fuzz/Fuzz.java` to get started!

### Writing and testing harnesses

- Select submodule that you want to develop a harness for --> switch the `tika-parsers` to the submodule name
- Remove previous build files from `/tmp/build_harness/`
- Change the `fuzz.java`file in /tmp/build_harness/tika-fuzz/....../Fuzz.java
- Rebuild after changes made to see if it compiles 
- Finally run fuzzer (see above)
- Profit

### Harness ideas

- "Crypto" related checks (something a fuzzer can find)
    https://github.com/centic9/jazzer/blob/b3de4a5a08453f1bc27bcbdd4cbbe80ace43d55a/examples/src/main/java/com/example/ExampleValueProfileFuzzer.java

- Add some decoy functions to slow down fuzzing or make it explore irrelevant paths

- Some of sub-components of Tika have test cases, you can refer to them for ideas
    one of them: https://github.com/apache/tika/blob/main/tika-core/src/test/java/org/apache/tika/parser/DummyParser.java

- some more examples: 
    https://github.com/0x34d/oss-fuzz/blob/5362821703ca5e37da2e3aa134a0539075de8402/projects/tomcat/ConnectorSendFileFuzzer.java#L168

please write some evil harness that break our pipeline ;)

### Two ways to find existing CVEs for in scope CWE's
1. Use CVE-Finder: https://github.com/shellphish-support-syndicate/CVE-Finder
(given a project name, this will find in-scope CVE and its details for you)

2. https://cve.mitre.org/cve/search_cve_list.html

### In scope Java Vulnerbilities
https://github.com/shellphish-support-syndicate/aixcc-sc-jazzer-examples/blob/main/README.md#magic-strings-and-triggers

# Modifications
`Dockerfile.extensions` here appends to `Dockerfile` in 
`aixcc-sc-challenge-002-jenkins-cp` 

`harness.patch` fixes `container_scripts/PipelineCommandUtilPovRunner.java` so that it can be fuzzed with Jazzer.

`dict_txt.txt` should be placed in `/classpath/`
`fuzz.sh` should be placed in `/`

# Core idea

We know for a fact that they will be using Jazzer for the sanitizer.
Which means that we can patch the harness to fuzz the target plugin using Jazzer.

# Threats to validity

There are some assumptions that we make in the current state of this component (described in `fuzz.sh`), which we need to find a proper solution for.

And the reason is that the directory structure within the image for CP-2 is very disorganized.

Currently in the CP-2, the control flows like this:
```
run.sh run_pov
->
    run_internal.sh pov
    ->
        PipelineCommandUtilPovRunner.java
        ->
            PipelineCommandUtilFuzzer.java
            ->
                doexecCommandUtils() <------- Vulnerable plugin
```


# LLM Modifier to update the harness code
```python
python3 updater.py --target_harness <path_to_target_harness_file> --modified_target_harness modified_harness.java
```

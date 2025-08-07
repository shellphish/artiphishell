Run AIxCC official jazzer harness and crash!

for the input create a tar.gz where /src and all other dirs are in the basedir.
`tar -cvzf ../aixcc-sc-challenge-002-jenkins-cp.tar.gz ./` (if you are in exemplar dir)

- build aixcc-jenkins-jazzer-harness image first and then run the pipeline. (I'm still working to make all run directly through to pipeline.yaml) 
`docker build . --no-cache -t aixcc-jenkins-jazzer-harness`
`./build_and_run.sh`

# Setup

## Pydatatask

```
git clone git@github.com:rhelmot/pydatatask.git
cd pydatatask
git checkout feat/declarative
pip install -e .
```

## Snapchange

```
git clone git@github.com:shellphish-support-syndicate/buildguy.git
git clone git@github.com:shellphish-support-syndicate/snapchange.git
cd snapchange
```
## Docker Image

Firstly, create the rootfs.
This can't be done inside the dockerfile since docker doesn't like mounting

```
pushd rootfs
./create-image.sh
popd
```

And now we can finally build the docker image
```
docker build -t snapchange .
# Go and get a cup of coffee, this is gonna take a while
```

Run the patch\_source command to patch the garfield source
```
docker run --rm -v <path containing garfield>:/data -v <path for patched source>:/output -it snapchange:latest /workdir/patch_source.sh /data/ /workdir/main.patch /output
```

Compile the patched garfield source
```
cd <path for patched source> && make && cp parser garfield.bin
```

And finally, start the fuzzer
```
docker run --privileged --rm -v <path containing garfield.bin>:/data -it snapchange:latest /workdir/fuzz.sh /data/garfield.bin
```

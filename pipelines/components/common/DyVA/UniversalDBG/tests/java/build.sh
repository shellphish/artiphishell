#!/usr/bin/bash

javac -g -d ./build *.java
pushd build
mkdir META-INF/
echo "Main-Class: HelloWorld" > META-INF/MANIFEST.MF
jar -cmf META-INF/MANIFEST.MF ../test.jar *
popd
rm -rf build

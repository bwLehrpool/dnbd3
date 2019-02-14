#!/bin/sh

./get-version.sh > version.txt
tar ckzf dnbd3.tar.gz src cmake CMakeLists.txt get-version.sh version.txt
rm -- version.txt


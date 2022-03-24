#!/bin/bash

mkdir -p output/conf
cp conf/conf.yaml output/conf
rm -rf output/data
mkdir output/data
chmod 777 output/data
mkdir output/data/before_analyse output/data/after_analyse output/data/ghsaid
chmod 777 output/data/before_analyse output/data/after_analyse output/data/ghsaid

go build -v -o ./output/main

cd output

./main
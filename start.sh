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

export https_proxy=socks5://localhost:1080
./main > $(date +"%Y_%m_%d_%H_%M.log") 2> $(date +"%Y_%m_%d_%H_%M.error.log")

cd ..
mv --backup=t output results

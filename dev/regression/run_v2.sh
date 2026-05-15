#!/bin/bash -l
#SBATCH -w gracesup1
#SBATCH --ntasks=1               
#SBATCH --time=12:00:00
#SBATCH --cpu-freq=3200000-3200000:performance

../../build-AArch64/winic -f 3.26 TP -o neoverse-v2.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT -o neoverse-v2.yaml > /dev/null

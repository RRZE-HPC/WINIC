#!/bin/bash -l
#SBATCH -w gracesup1
#SBATCH --ntasks=1               
#SBATCH --time=12:00:00
#SBATCH --cpu-freq=3200000-3200000:performance

module load likwid/grace

likwid-pin -c 1 ../../build-Arch64-v22/winic -f 3.26 TP --memory=none  -o neoverse-v2.yaml > /dev/null
likwid-pin -c 1 ../../build-Arch64-v22/winic -f 3.26 LAT --memory=none  -o neoverse-v2.yaml > /dev/null

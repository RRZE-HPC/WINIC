#!/bin/bash -l
#SBATCH -w genoa1
#SBATCH --ntasks=1
#SBATCH --time=12:00:00
#SBATCH --cpu-freq=1500000-1500000:performance
#SBATCH -C hwperf

module load likwid/5.2.2 && likwid-setFrequencies -t 0 && likwid-setFrequencies -f 1.5

../../build-x86/winic -f 1.5 TP -o zen4.yaml > /dev/null
../../build-x86/winic -f 1.5 LAT -o zen4.yaml > /dev/null
# ../../build-x86/winic -f 1.5 TP -o winic_zen4_r4fp7.yaml --regInit 0x401C000000000000 > /dev/null
# ../../build-x86/winic -f 1.5 LAT -o winic_zen4_r4fp7.yaml --regInit 0x401C000000000000 > /dev/null

#!/bin/bash -l
#SBATCH -w icx36
#SBATCH --ntasks=1               
#SBATCH --time=12:00:00
#SBATCH --cpu-freq=2400000-2400000:performance

srun --cpu-freq=2400000-2400000:performance ../../build-x86/winic -f 2.4 TP -o ./icx.yaml > /dev/null
srun --cpu-freq=2400000-2400000:performance ../../build-x86/winic -f 2.4 LAT -o ./icx.yaml > /dev/null
# srun --cpu-freq=2400000-2400000:performance ../../build-x86/winic -f 2.4 TP -o ./icx_rfp7.yaml --regInit 0x401C000000000000 > /dev/null
# srun --cpu-freq=2400000-2400000:performance ../../build-x86/winic -f 2.4 LAT -o ./icx_rfp7.yaml --regInit 0x401C000000000000 > /dev/null

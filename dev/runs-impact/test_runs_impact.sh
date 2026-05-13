#!/bin/bash -l
#SBATCH -w gracesup1
#SBATCH --ntasks=1               
#SBATCH --time=12:00:00
#SBATCH --cpu-freq=3200000-3200000:performance

../../build-AArch64/winic -f 3.26 LAT --runs 3 -o runs3_1.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 3 -o runs3_2.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 3 -o runs3_3.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 3 -o runs3_4.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 3 -o runs3_5.yaml > /dev/null

../../build-AArch64/winic -f 3.26 LAT --runs 4 -o runs4_1.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 4 -o runs4_2.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 4 -o runs4_3.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 4 -o runs4_4.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 4 -o runs4_5.yaml > /dev/null

../../build-AArch64/winic -f 3.26 LAT --runs 5 -o runs5_1.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 5 -o runs5_2.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 5 -o runs5_3.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 5 -o runs5_4.yaml > /dev/null
../../build-AArch64/winic -f 3.26 LAT --runs 5 -o runs5_5.yaml > /dev/null
 
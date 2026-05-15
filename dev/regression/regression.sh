#!/bin/bash -l

cd ../..
source ./venv/bin/activate
python3 -m analysis.cli diff --mode BOTH -v data/zen4/zen4.yaml dev/regression/zen4.yaml > dev/regression/regression_zen4.log
python3 -m analysis.cli diff --mode BOTH -v data/icx/icx.yaml dev/regression/icx.yaml > dev/regression/regression_icx.log
python3 -m analysis.cli diff --mode BOTH -v data/neoverse-v2/neoverse-v2.yaml dev/regression/neoverse-v2.yaml > dev/regression/regression_v2.log
python3 -m analysis.cli diff --mode BOTH -v data/spacemit-x60/spacemit-x60.yaml dev/regression/spacemit-x60.yaml > dev/regression/regression_x60.log

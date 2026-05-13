# Test impact of --runs

To have a more solid reasoning for what should be set as standard value for WINICs `--runs` parameter here are scripts to measure the mean standard deviation of the obtained metrics, depending on the number of benchmark repititions. 

## Results
On a grace superchip (latency values):

for 3 per kernel we get a std deviation score of 0.0623 \
for 4 per kernel we get a std deviation score of 0.0115 \
for 5 per kernel we get a std deviation score of 0.0112 

(standard deviation with penalty for missing values)

this suggests 4 runs may be the sweetspot between accuracy and performance.

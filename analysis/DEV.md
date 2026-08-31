# Notes for developers

## Decisions in comparison
uops.info zen4 `VSQRTPS_Z (ZMM, K, M512)` has only one latency:
`<latency start_op="3" target_op="1" cycles_addr="23" cycles_addr_is_upper_bound="1" cycles_addr_index="23" cycles_addr_index_is_upper_bound="1"/>`
Since WINIC does not measure the address and index operand latencies, this is treated as having no value by the comparison logic.
It does not count towards "No match". 


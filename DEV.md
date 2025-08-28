# Notes for Developers

## LLVM Instruction Format

LLVM instructions store a read from a register and a write to the same register as two distinct operands:

- **LLVM operand layout:**
  ```
  operands: [op0: reg(w), op1: reg(r), op2: imm(r)]
  numDefs: 1
  constraints: [op0 == op1]
  ```

  - `op0`: register (written)
  - `op1`: register (read)
  - `op2`: immediate (read)
  - `numDefs: 1`: one defined (written) operand
  - `constraints: [op0 == op1]`: op0 and op1 must be the same register

- **Corresponding assembly-style operand layout:**
  ```
  operands: [op0: reg(rw), op1: imm(r)]
  ```
  - `op0`: register (read/write)
  - `op1`: immediate (read)

### Visualization

Below is a mapping between LLVM and assembly operand layouts:

```
LLVM:   [op0: reg(w)]   [op1: reg(r)]   [op2: imm(r)]
             |                |              |
             |<- constraint ->|              |
                     |                       |
             +-------+       +---------------+
             |               |
ASM:    [op0: reg(rw)]   [op1: imm(r)]
```

- The constraint `op0 == op1` merges the two operands into a single read/write register in the assembly format.

## LLVM Name Decoding Example

### Instruction: `VFMADD132PDZ256mbkz`
```
VFMADD {132|213|231}  {P|S}  {D|S}  { |Y|Z}  {128|256| }  {m|r} {b| }  {k|kz| }
                  |     |      |       |          |         |     |       |
Operand Order   <-+     |      |       |          |         |     |       |
Packed/Scalar   <-------+      |       |          |         |     |       |
Single/Double   <--------------+       |          |         |     |       |
AVX Width       <----------------------+          |         |     |       |
Vector Size     <---------------------------------+         |     |       |
Memory/Register <-------------------------------------------+     |       |
Broadcast       <-------------------------------------------------+       |
Masking/Zeroing <---------------------------------------------------------+
```

### Example Mapping
- `VFMADD132PDZ256mbkz`
  - **132** → Operand order  
  - **P** → Packed  
  - **D** → Double precision  
  - **Z** → AVX-512 (ZMM registers)  
  - **256** → 256-bit vector width  
  - **m** → Memory as 3rd operand  
  - **b** → Broadcast  
  - **kz** → Masked destination with zeroing  



## Error Code reference

| ErrorCode               | Type    | Allows Manual Correction|Explanation|
|-------------------------|---------|-------------------------|-----------|
| SUCCESS                 | success | N/A | Operation completed successfully|
| NO_ERROR_CODE           | default | N/A | No error code assigned, should not occurr as result of measuring an instruciton|
| W_MULTIPLE_DEPENDENCIES | warning | yes | Detected Multiple dependencies between the instructions generated. The result may be improved manually|
| SKIP_NO_MNEMONIC    | skip    | no  | Skipped: does not have a mnemonic and therefore does not emit machine instruction|
| S_INSTRUCION_PREFIX     | skip    | no  | Skipped: just an instruction prefix|
| S_IS_CALL               | skip    | no  | Skipped: calls cannot be measured|
| S_IS_CODE_GEN_ONLY      | skip    | no  | Skipped: instruction is for code generation only|
| S_IS_BRANCH             | skip    | no  | Skipped: branches cannot be measured|
| S_IS_META_INSTRUCTION   | skip    | no  | Skipped: meta-instruction, not executed directly|
| S_IS_RETURN             | skip    | no  | Skipped: returns cannot be measured|
| S_IS_X87FP              | skip    | yes | Skipped: x87 floating-point instruction. Excluded for better performance, can be measured manually|
| S_MANUALLY              | skip    | yes | Skipped: marked for manual skipping|
| S_MAY_LOAD              | skip    | no  | Skipped: instruction may load from memory|
| S_MAY_STORE             | skip    | no  | Skipped: instruction may store to memory|
| S_MEMORY_OPERAND        | skip    | no  | Skipped: instruction has memory operand, this does not enforce mayLoad or mayStore flag|
| S_PCREL_OPERAND         | skip    | no  | Skipped: instruction has PC-relative operand|
| S_PSEUDO_INSTRUCTION    | skip    | no  | Skipped: pseudo-instruction, not real hardware instruction|
| S_UNKNOWN_OPERAND       | skip    | no  | Skipped: instruction has unknown operand type|
| E_ASSEMBLY              | error   | no  | Asembly failed. The instruction is probably not supported on the platform|
| E_CPU_DETECT            | error   | yes | LLVM Failed to detect the CPU. This did not happen yet, there is a (untested) --cpu flag to set the cpu manually. |
| E_EXEC                  | error   | no  | Execution failed. This is an internal problem|
| E_FILE                  | error   | no  | File operation failed. This is an internal problem|
| E_FORK                  | error   | no  | Process fork failed. This is an internal problem|
| E_GENERIC               | error   | no  | Generic/unspecified error|
| E_ILLEGAL_INSTRUCTION   | error   | no  | Benchmarking failed on SIGILL, the instruction is probably not supported on the platform|
| E_MMAP                  | error   | no  | Memory mapping failed. This is an internal problem|
| E_NO_HELPER             | error   | no  | A helper instruction is needed to measure this. When measuring single instructions one may be provided|
| E_NO_REGISTERS          | error   | no  | Not enough registers available to generate benchmark|
| E_SIGNAL                | error   | N/A | Benchmarking failed on a signal other than SIGSEGV, SIGILL and SIGFPE. This is rare and should be investigated|
| E_SIGSEGV               | error   | no  | Segmentation fault occurred. Can happen on many kinds of instructions|
| E_TEMPLATE              | error   | no  | Template processing failed. This is an internal problem|
| E_UNSUPPORTED_ARCH      | error   | no  | Either LLVM Failed to detect the target, or this is an architectures other than x86, AArch64 and RISCV|
| E_UNROLL_ANOMALY        | error   | yes | When unrolling the loop, the time per instruction increased significantly. The instruciton may still be measured manually. The cause for this is currently unknown|
| E_UNREACHABLE           | error   | no  | Unreachable code executed. This should never happen. Please file a bug report if you encounter this. |

## Safety

MCInstPrinter->PrintInst can fail or even segfault if the operands are not set correctly. It is therefore only used in functions that are run in a subprocess.
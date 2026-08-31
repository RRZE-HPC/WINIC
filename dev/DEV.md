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

## Important LLVM source files
`llvm-project/llvm/include/llvm/MC/MCInstrDesc.h`
- `getNumOperands()`
- `getNumDefs()`
- `isReturn()`
- `mayLoad()`
- `mayStore()`
- `hasImplicitUseOfPhysReg()`
- `OperandType` (register/immediate/memory)
- `MCOperandInfo->RegClass`

`llvm-project/llvm/include/llvm/MC/MCRegisterInfo.h`
- `MCRegisterClass`
    - `getSizeInBits()`
- `MCRegisterDesc`
    - `Name`
- MCRegisterInfo
    - `subregs(MCRegister Reg)`
    - `superregs(MCRegister Reg)`
    - `regsOverlap(MCRegister RegA, MCRegister RegB)`

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

Note that LLVM instruction names as well as opcodes can change across different LLVM releases.

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

## LLVM operand info
`llvm-mc` can show the number and order of operands of a disassembled instruction, e.g.: 
```bash
echo "addq %rax, 8(%rbx)" | llvm-mc --show-inst
```
produces
```
<MCInst #631 ADD64mr
 <MCOperand Reg:53> // base (%rbx)
 <MCOperand Imm:1> // scale
 <MCOperand Reg:0> // ind
 <MCOperand Imm:8> // offset
 <MCOperand Reg:0> // segment
 <MCOperand Reg:51>> // %rax
```
Note that on x86 all of the operands that belong to the memory access are `MCOI::OPERAND_MEMORY` even though they are registers and immediates.

On AArch64 memory operands are handled differently, e.g.:
```
ldr     d0, [x9, #4]!                   
<MCInst #5044 LDRDpre
 <MCOperand Reg:X9> // base write back
 <MCOperand Reg:D0> // load destination
 <MCOperand Reg:X9> // base
 <MCOperand Imm:4>> // offset
```

However, there are multiple different addressing modes and not all are handled by WINIC (e.g. reg-reg addressing).

On RISCV:
```
ld      t0, 8(t1)                       
<MCInst #12666 LD
 <MCOperand Reg:48> // destination
 <MCOperand Reg:49> // base
 <MCOperand Imm:8>> // offset
```

Generic operand info definitions come from `llvm-project/llvm/include/llvm/MC/MCInstrDesc.h`. \
The `MCOI::OperandType` enum has `MCOI::OPERAND_FIRST_TARGET` as last entry, then 
target specific operand info definitions start from there (they come from `llvm-project/llvm/lib/Target/RISCV/MCTargetDesc/RISCVBaseInfo.h` and equivalents)

## Misc LLVM Info
- isPseudo is only set to 1 for instructions that are LLVM pseudo instructions. CMOV_VR128 is not pseudo because its assembly string "#CMOV__VR128 PSEUDO!" can be emmitted and then processed by an assembler.
- LLVMs mayLoad/mayStore information is not 100% reliable

## Upgrading the LLVM version
When upgrading to a newer release of LLVM one should:
### Compare key files used by WINIC
```bash 
git fetch --tags
git diff llvmorg-<old> llvmorg-<new> -- llvm/include/llvm/MC/MCInstrDesc.h
```

### Compare Instruction Info
Use WINIC in `INFO` mode on both versions to get comparable overviews on instruction names with operands and flags.

### Regression test
Use the scripts in `dev/regression` to test if there are major changes in the results

## LLVM Upgrade History
### 20.1.5 -> 22.1.8:
x86:
- many AVX512 instruction variants with broadcasting were removed such as `VADDPDZ256rrb`, all i checked resulted in `ILLEGAL_INSTRUCTION` when measured with WINIC
- some mayLoad flag fixes
- VPDPBSSDSZ128m and similar instructions were renamed to VPDPBSSDSZ128**r**m
- VSM3RNDS2rm and similar instructions were renamed to VSM3RNDS2rmi

AArch64: \
- added some instructions e.g. `ADDSUBP_ZZZ_B`
- reduced number of `Unknown` operands (~2500 -> ~300) by converting them to `Immediate` or removing them
    - the ones i tested that are left do not care if the immediate is present or not
- fixed some mayLoad and mayStore flags
- added a few instruction variants

LLVM interface:
- Target::createTargetMachine, Target::createMCAsmInfo etc now take a `Triple` instead of a `StringRef`


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

## Limitations
WINIC has some non-obvious limitations:
- The path over text representation -> assembler -> benchmark binary loses some information. There are instruction forms where there are different encodings for the same semantics, we do not have any control over which one the assembler chooses.
- WINIC can not generate latency chains on base/index registers of memory operands

## IWYU Makefile
The MAKEFILE is a helper to run LLVMs include-what-you-use on all WINIC source files. It expects the LLVM repo in `llvm-project` and a x86 llvm build in `llvm-build-x86` (generate using `setup.sh --dir x86`)
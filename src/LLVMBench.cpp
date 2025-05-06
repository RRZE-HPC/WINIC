#include "LLVMBench.h"

#include "BenchmarkGenerator.h" // for genInst4, isValid, whic...
#include "CustomDebug.h"        // for dbg, debug
#include "ErrorCode.h"          // for ErrorCode, ecToString
#include "Globals.h"            // for LatMeasurement4, Depend...
#include "LLVMBench.h"
#include "LLVMEnvironment.h"                 // for LLVMEnvironment
#include "llvm/ADT/ArrayRef.h"               // for ArrayRef
#include "llvm/ADT/StringRef.h"              // for StringRef
#include "llvm/CodeGen/TargetRegisterInfo.h" // for TargetRegisterInfo
#include "llvm/MC/MCInst.h"                  // for MCInst, MCOperand
#include "llvm/MC/MCInstrDesc.h"             // for MCInstrDesc
#include "llvm/MC/MCInstrInfo.h"             // for MCInstrInfo
#include "llvm/MC/MCRegister.h"              // for MCRegister
#include "llvm/MC/MCRegisterInfo.h"          // for MCRegisterInfo
#include "llvm/Support/raw_ostream.h"        // for raw_fd_ostream, raw_ost...
#include "llvm/TargetParser/Triple.h"        // for Triple
#include <algorithm>                         // for min_element, max
#include <csignal>                           // for SIGSEGV, size_t, SIGILL
#include <cstdio>                            // for printf, NULL, fflush
#include <cstdlib>                           // for exit, atoi, EXIT_SUCCESS
#include <ctype.h>                           // for isdigit
#include <dlfcn.h>                           // for dlsym, dlclose, dlopen
#include <fcntl.h>                           // for open, O_WRONLY, O_TRUNC
#include <fstream>                           // for basic_ostream, operator<<
#include <getopt.h>                          // for required_argument, option
#include <iostream>                          // for cerr, cout
#include <iterator>                          // for move_iterator, make_mov...
#include <map>                               // for map, operator!=, operat...
#include <string.h>                          // for strcmp
#include <string>                            // for basic_string, hash, cha...
#include <sys/mman.h>                        // for mmap, munmap, MAP_ANONY...
#include <sys/time.h>                        // for timeval, gettimeofday
#include <sys/types.h>                       // for pid_t
#include <sys/wait.h>                        // for waitpid
#include <tuple>                             // for tuple, get, tie
#include <unistd.h>                          // for optarg, _exit, fork, dup2
#include <unordered_map>                     // for unordered_map, operator!=
#include <unordered_set>                     // for unordered_set
#include <vector>                            // for vector

// #include "MCTargetDesc/X86MCTargetDesc.h"
// #include "MCTargetDesc/X86BaseInfo.h"

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

void *globalHandle = nullptr;

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, int N, unsigned Runs) {
    dbg(__func__, "clang path: ", CLANG_PATH);
    std::string clangPath = CLANG_PATH;
    if (clangPath == "usr/bin/clang") {
        std::cerr << "CLANG_PATH not set, using default" << std::endl;
    }
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return {ERROR_FILE, {}};
    }
    asmFile << Assembly.generateAssembly();
    asmFile.close();
    if (dbgToFile) {
        // TODO make path relative
        std::string debugPath =
            "/home/hpc/ihpc/ihpc149h/bachelor/llvm-project/own_tools/llvm-bench/debug.s";
        std::ofstream debugFile(debugPath);
        dbg(__func__, "debug written to path: ", debugPath.data());
        if (!debugFile) {
            std::cerr << "Failed to create debug file at " << debugPath.data() << std::endl;
            return {ERROR_FILE, {}};
        }
        debugFile << Assembly.generateAssembly();
        debugFile.close();
    }

    dbg(__func__, "assembling benchmark");

    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    // "gcc -x assembler-with-cpp -shared -mfp16-format=ieee " + sPath + " -o " + oPath + " 2>
    // gcc_out";

    // slightly worse performance than fork
    //  std::string compiler = CLANG_PATH;
    //  std::string command = compiler + " -x assembler-with-cpp -shared " + sPath + " -o " + oPath;
    //  if (dbgToFile)
    //      command += " 2> assembler_out.log";
    //  else
    //      command += " 2> /dev/null";
    //  if (system(command.data()) != 0) return {ERROR_ASSEMBLY, {-1}};

    // slightly better performance
    pid_t pid = fork();
    if (pid == 0) { // Child
        int fd;
        if (dbgToFile) {
            fd = open("assembler_out.log", O_WRONLY | O_TRUNC);
            if (fd == -1) {
                perror("open assembler_out.log failed");
                _exit(127);
            }
        } else {
            fd = open("/dev/null", O_WRONLY);
            if (fd == -1) {
                perror("open /dev/null failed");
                _exit(127);
            }
        }
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        execl(CLANG_PATH, "clang", "-x", "assembler-with-cpp", "-shared", sPath.data(), "-o",
              oPath.data(), nullptr);
        _exit(127);       // execl failed
    } else if (pid > 0) { // Parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            if (WEXITSTATUS(status) == 127) return {ERROR_EXEC, {}};
            return {ERROR_ASSEMBLY, {}};
        }
    }
    dbg(__func__, "assembly complete, loading shared library");

    // from ibench
    if ((globalHandle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        return {ERROR_FILE, {}};
    }
    // get handles to function in the assembly file
    std::unordered_map<std::string, double (*)(int)> benchFunctionMap;
    std::unordered_map<std::string, double (*)()> initFunctionMap;
    for (std::string functionName : Assembly.getInitFunctionNames()) {
        auto functionPtr = (double (*)())dlsym(globalHandle, functionName.data());
        if (functionPtr == NULL) {
            fprintf(stderr, "dlsym: couldn't find function %s\n", functionName.data());
            return {ERROR_GENERIC, {}};
        }
        initFunctionMap[functionName] = functionPtr;
    }
    for (std::string functionName : Assembly.getBenchFunctionNames()) {
        auto functionPtr = (double (*)(int))dlsym(globalHandle, functionName.data());
        if (functionPtr == NULL) {
            fprintf(stderr, "dlsym: couldn't find function %s\n", functionName.data());
            return {ERROR_GENERIC, {}};
        }
        benchFunctionMap[functionName] = functionPtr;
    }
    // may have results from prior runs
    dbg(__func__, "starting benchmarks");
    struct timeval start, end;
    std::unordered_map<std::string, std::list<double>> benchtimes;

    for (auto [benchFunctionName, benchFunctionPointer] : benchFunctionMap) {
        auto benchFunction = benchFunctionPointer;
        auto initFunction = initFunctionMap[Assembly.getInitNameFor(benchFunctionName)];
        for (unsigned i = 0; i < Runs; i++) {
            if (initFunction) (*initFunction)();

            gettimeofday(&start, NULL);
            (*benchFunction)(N);
            gettimeofday(&end, NULL);

            auto &list = benchtimes[benchFunctionName];
            list.insert(list.end(),
                        (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
        }
    }

    dlclose(globalHandle);
    return {SUCCESS, benchtimes};
}

std::list<DependencyType> getDependencies(MCInst Inst1, MCInst Inst2) {
    std::list<DependencyType> dependencies;
    const MCInstrDesc &desc1 = env.MCII->get(Inst1.getOpcode());
    const MCInstrDesc &desc2 = env.MCII->get(Inst2.getOpcode());
    // collect all registers Inst1 will define
    std::set<MCRegister> defs1;
    for (unsigned i = 0; i < desc1.getNumDefs(); i++) {
        if (Inst1.getOperand(i).isReg()) defs1.insert(Inst1.getOperand(i).getReg());
    }
    for (MCRegister implDef : desc1.implicit_defs()) {
        defs1.insert(implDef);
    }
    // collect all registers Inst2 will use
    std::set<MCRegister> uses2;
    for (unsigned i = desc2.getNumDefs(); i < desc2.getNumOperands(); i++) {
        if (Inst2.getOperand(i).isReg()) uses2.insert(Inst2.getOperand(i).getReg());
    }
    for (MCRegister implUse : desc2.implicit_uses()) {
        uses2.insert(implUse);
    }
    // create dependencyType for every register which is defined by 1 and used by 2
    for (MCRegister def : defs1)
        for (MCRegister use : uses2)
            if (def == use)
                dependencies.emplace_back(
                    DependencyType(Operand::fromRegister(def), Operand::fromRegister(use)));
    return dependencies;
}

std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount,
                                             double Frequency) {
    // correct the result using one measurement with NumInst and one with 2*NumInst. This removes
    // overhead of e.g. the loop instructions themselves see README for explanation TODO
    double instRuntime = UnrolledRuntime - Runtime;
    // runtime[usec -> sec] * Frequency[GHz -> Hz] / number of instructions executed
    double cyclesPerInstruction = (instRuntime / 1e6) * (Frequency * 1e9) / (NumInst * LoopCount);

    if (instRuntime * 2 > UnrolledRuntime * 1.1) {
        // this is unlikely to be a good measurement
        out(*ios,
            "Execution time increases overproportional when unrolling, which should not happen. "
            "Runtime: ",
            Runtime, " UnrolledRuntime: ", UnrolledRuntime);
        return {ERROR_GENERIC, -1};
    }
    // for some instructions unrolling slightly decreases throughput e.g. ADC16ri8 with helper
    // TEST64rr (TODO investigate why). In those cases the unrolled time is not used for correction
    if (instRuntime * 2 > UnrolledRuntime)
        cyclesPerInstruction = (Runtime / 1e6) * (Frequency * 1e9) / (NumInst * LoopCount);
    return {SUCCESS, cyclesPerInstruction};
}

std::tuple<ErrorCode, int, std::map<unsigned, MCRegister>>
getTPHelperInstruction(unsigned Opcode, bool BreakDependencyOnSuperreg) {
    // first check if this instruction needs a helper
    // generate two instructions and check for dependencys
    std::set<MCRegister> usedRegs;
    auto [ec1, inst1] = genInst4(Opcode, {}, usedRegs);
    auto [ec2, inst2] = genInst4(Opcode, {}, usedRegs);
    std::list<DependencyType> dependencies = getDependencies(inst1, inst2);
    if (dependencies.empty()) return {SUCCESS, -1, {}}; // no helper needed
    if (dependencies.size() > 1) {
        dbg(__func__, "multiple dependencies");
        // this instruction has multiple dependencies on itself, this
        // is currently not supported
        return {ERROR_NO_HELPER, -1, {}};
    }
    // this instruction will always have one dependency on itself. We have to break this by
    // interleaving another instruction. The other instruction has to:
    // 1. be measured already
    // 2. define the used register of the dependency
    // 3. not be dependent on the current instruction
    auto dep = dependencies.front();
    auto useReg = dep.useOp.getRegister();

    unsigned helperOpcode = -1;
    std::map<unsigned, MCRegister> helperConstraints;
    // first we try opcodes in the priorityTPHelper list. Those are allowed to be used as helper
    // even if they write not to the register itself but a superregister
    // on Zen4 there is a partial write penalty when writing to just a part of a GPR
    // priorityTPHelper can be used to prevent this from happening
    for (unsigned possibleHelper : priorityTPHelper) {
        TPResult tpRes = throughputDatabase[possibleHelper];
        dbg(__func__, "checking possible ", tpRes.ec, " ", tpRes.lowerTP);
        if (tpRes.ec != SUCCESS) continue;  // no value
        if (tpRes.lowerTP < 0.25) continue; // we dont trust values this low
        for (MCRegister possibleWriteReg : env.getPossibleWriteRegs(possibleHelper)) {
            if (env.TRI->isSuperRegisterEq(useReg, possibleWriteReg)) {
                dbg(__func__, "found reg ", possibleHelper);
                useReg = possibleWriteReg;
                auto [EC, opIndex] = whichOperandCanUse(possibleHelper, "def", useReg);
                // we checked the instruction is able to define the register
                if (EC != SUCCESS) return {ERROR_UNREACHABLE, -1, {}};
                if (opIndex != -1)
                    helperConstraints.insert({(unsigned)opIndex, useReg});
                else {
                    // whichOperandCanUse returned -1 so the requred register is defined
                    // implicitly and we dont need to constrain the helper instruction
                }
                // check 3. generate a pair of instructions to check for unwanted dependencys
                // this will catch implicit dependencys e.g. instruction writes to EFLAGS and
                // helper reads EFLAGS
                // explicit dependencys e.g. ADD16ri can define ax but if it does it also uses
                // ax so it can't be used as helper
                std::set<MCRegister> tmpUsedRegs;
                auto [ec1, inst] = genInst4(Opcode, {}, tmpUsedRegs);
                auto [ec2, helperInst] = genInst4(possibleHelper, helperConstraints, tmpUsedRegs);
                if (ec1 != SUCCESS || ec2 != SUCCESS) continue;
                if (!getDependencies(inst, helperInst).empty()) continue;
                helperOpcode = possibleHelper;
                break;
            }
        }
    }
    if (helperOpcode != -1) return {SUCCESS, helperOpcode, helperConstraints};
    dbg(__func__, "no prio helper");
    // the no priorityHelper can be used, try all other instructions now
    for (auto [possibleHelper, res] : throughputDatabase) {
        if (res.ec != SUCCESS) continue;
        if (res.lowerTP < 0.25) continue;
        std::set<MCRegister> possibleWrites = env.getPossibleWriteRegs(possibleHelper);
        if (possibleWrites.find(useReg) != possibleWrites.end()) {
            auto [EC, opIndex] = whichOperandCanUse(possibleHelper, "def", useReg);
            if (EC != SUCCESS) return {ERROR_UNREACHABLE, -1, {}};
            if (opIndex != -1) helperConstraints.insert({(unsigned)opIndex, useReg});
            std::set<MCRegister> tmpUsedRegs;
            auto [ec1, inst] = genInst4(Opcode, {}, tmpUsedRegs);
            auto [ec2, helperInst] = genInst4(possibleHelper, helperConstraints, tmpUsedRegs);
            if (ec1 != SUCCESS || ec2 != SUCCESS) continue;
            if (!getDependencies(inst, helperInst).empty()) continue;
            helperOpcode = possibleHelper;
            break;
        }
    }
    if (helperOpcode == -1) return {ERROR_NO_HELPER, -1, {}};
    return {SUCCESS, helperOpcode, helperConstraints};
}

std::tuple<ErrorCode, double, double> measureThroughput(unsigned Opcode, double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    // TODO do this much earlier
    const MCInstrDesc &desc = env.MCII->get(Opcode);
    if (isValid(desc) != SUCCESS) return {isValid(desc), -1, -1};
    out(*ios, "-----", env.MCII->getName(Opcode).data(), "-----");
    unsigned numInst = 12;
    double n = 1000000; // loop count
    AssemblyFile assembly;
    ErrorCode ec;
    std::set<MCRegister> usedRegs;
    std::unordered_map<std::string, std::list<double>> benchResults;

    auto [ec1, helperOpcode, helperConstraints] = getTPHelperInstruction(Opcode, true);
    if (ec1 != SUCCESS) return {ec1, -1, -1};

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    // if no helper is needed helperOpcode is -1 and genTPBenchmark will ignore it
    std::tie(ec, assembly) =
        genTPBenchmark(Opcode, &numInst, 1, usedRegs, helperConstraints, helperOpcode);
    if (ec != SUCCESS) return {ec, -1, -1};
    dbg(__func__, "calling run");
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1, -1};

    // take minimum of runs (naming convention of funcitons in genTPBenchmark)
    double time1 = *std::min_element(benchResults["tp"].begin(), benchResults["tp"].end());
    double time2 =
        *std::min_element(benchResults["tpUnroll2"].begin(), benchResults["tpUnroll2"].end());

    auto [EC, correctedTP] = calculateCycles(time1, time2, numInst, n, Frequency);
    if (helperOpcode > -1) {
        // we did use a helper, this can change the TP
        // TODO change once port distribution is implemented
        dbg(__func__, "correcting ", correctedTP, " with ", env.MCII->getName(helperOpcode).data(),
            " ", throughputDatabase[helperOpcode].lowerTP);
        out(*ios, "Helper: ", env.MCII->getName(helperOpcode).data(), " ",
            throughputDatabase[helperOpcode].lowerTP);
        double tpSamePorts = correctedTP - throughputDatabase[helperOpcode].lowerTP;
        if (tpSamePorts < 1 / 4) {
            out(*ios, "Assuming instruction and helper use different ports, otherwise TP would be ",
                tpSamePorts);
            return {SUCCESS, correctedTP, correctedTP};
        }
        out(*ios, "No hints if instruction and helper use same ports, TP can be in range ",
            tpSamePorts, " - ", correctedTP);
        return {SUCCESS, tpSamePorts, correctedTP};
    }

    return {SUCCESS, correctedTP, correctedTP};
}

std::pair<ErrorCode, double> measureLatency(unsigned Opcode, double Frequency) {
    const MCInstrDesc &desc = env.MCII->get(Opcode);
    if (isValid(desc) != SUCCESS) return {isValid(desc), {}};

    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    // unsigned numInst2 = 24;
    double n = 1000000; // loop count
    ErrorCode ec;
    AssemblyFile assembly;
    int helperOpcode;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(ec, assembly, helperOpcode) = genLatBenchmark(Opcode, &numInst1, &helperInstructions);
    if (ec != SUCCESS) return {ec, -1};
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1};

    // take minimum of runs "latency" and "latencyUnrolled" naming convention in
    double time1 =
        *std::min_element(benchResults["latency"].begin(), benchResults["latency"].end());
    double time2 = *std::min_element(benchResults["latencyUnrolled"].begin(),
                                     benchResults["latencyUnrolled"].end());
    // dbg(__func__, "time1: ", time1, " time2: ", time2);

    // predict if loop instructions interfere with the execution
    // see README for explanation TODO
    double loopInstr2 = numInst1 * (time2 - 2 * time1) / (time1 - time2); // calculate unroll 1->2
    if (loopInstr2 < -1) {
        // throughput decreases significantly when unrolling, this should not be possible
        std::printf("   anomaly detected during measurement of %s:\n",
                    env.MCII->getName(Opcode).data());
        dbg(__func__, loopInstr2, " time1: ", time1, " time2: ", time2);
        for (auto time : benchResults["latencyUnrolled"]) {
            std::printf("   %.3f ", time);
        }
        return {ERROR_GENERIC, -1};
    }
    loopInstr2 = std::max(loopInstr2, 0.0);
    double uncorrected = time1 / (1e6 * numInst1 / Frequency * (n / 1e9));
    dbg(__func__, "uncorrected: ", uncorrected, " loopInstr2: ", loopInstr2);
    double corrected = time1 / (1e6 * (numInst1 + loopInstr2) / Frequency * (n / 1e9));

    // if a helper instruction was used subtract its latency
    if (helperOpcode != -1) corrected -= latencyDatabase[helperOpcode];
    if (corrected > 0) {
        // reasonable result, save this as helper for other instructions if not present yet
        // TODO is this check neccesary?
        bool alreadyInHelpers = false;
        for (auto helperInst : helperInstructions) {
            auto [helperOpc, helperReadRegs, helperWriteRegs] = helperInst;
            if (helperOpc == Opcode) {
                alreadyInHelpers = true;
                break;
            }
        }
        if (!alreadyInHelpers) {
            auto reads = env.getPossibleReadRegs(Opcode);
            auto writes = env.getPossibleWriteRegs(Opcode);
            helperInstructions.insert(helperInstructions.end(), {Opcode, reads, writes});
        }
    }

    return {SUCCESS, corrected};
}

std::pair<ErrorCode, double> measureLatency4(std::list<LatMeasurement4> Measurements,
                                             double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    // unsigned numInst2 = 24;
    double n = 1000000; // loop count
    ErrorCode ec;
    AssemblyFile assembly;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(ec, assembly) = genLatBenchmark4(Measurements, &numInst1);
    if (ec != SUCCESS) return {ec, -1};
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1};

    // take minimum of runs. "latency" and "latencyUnrolled" is naming convention defined in
    // runBenchmark()
    double time1 =
        *std::min_element(benchResults["latency"].begin(), benchResults["latency"].end());
    double time2 = *std::min_element(benchResults["latencyUnrolled"].begin(),
                                     benchResults["latencyUnrolled"].end());
    double cycles;
    std::tie(ec, cycles) = calculateCycles(time1, time2, numInst1, n, Frequency);
    if (ec != SUCCESS) {
        // throughput decreases significantly when unrolling, this should not be possible
        std::string chainString = "";
        for (auto m : Measurements) {
            chainString += env.MCII->getName(m.opcode).data();
            chainString += " -> ";
        }
        std::printf("   anomaly detected during measurement of %s:\n", chainString.data());
        for (auto time : benchResults["latencyUnrolled"]) {
            std::printf("   %.3f ", time);
        }
        return {ERROR_GENERIC, -1};
    }

    return {SUCCESS, cycles};
}

std::tuple<ErrorCode, double, double> measureInSubprocess(unsigned Opcode, double Frequency,
                                                          std::string Type) {
    // allocate memory to communicate result
    double *sharedLowerBound = static_cast<double *>(
        mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    double *sharedUpperBound = static_cast<double *>(
        mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ErrorCode *sharedEC = static_cast<ErrorCode *>(
        mmap(NULL, sizeof(ErrorCode), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));

    if (sharedUpperBound == MAP_FAILED || sharedLowerBound == MAP_FAILED ||
        sharedEC == MAP_FAILED) {
        perror("mmap");
        return {ERROR_MMAP, -1, -1};
    }

    pid_t pid = fork();
    if (pid == -1) {
        return {ERROR_FORK, -1, -1};
    }

    if (pid == 0) { // Child process
        ErrorCode ec;
        double lower;
        double upper;
        if (Type == "t")
            std::tie(ec, lower, upper) = measureThroughput(Opcode, Frequency);
        else
            std::tie(ec, lower) = measureLatency(Opcode, Frequency);

        *sharedLowerBound = lower;
        *sharedUpperBound = upper;
        *sharedEC = ec;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return {ERROR_SIGSEGV, -1, -1};
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGILL) return {ILLEGAL_INSTRUCTION, -1, -1};
        if (WIFSIGNALED(status)) return {ERROR_SIGNAL, -1, -1};
        if (WEXITSTATUS(status) != EXIT_SUCCESS) return {ERROR_GENERIC, -1, -1};

        ErrorCode ec = *sharedEC;
        double lower = *sharedLowerBound;
        double upper = *sharedUpperBound;
        munmap(sharedLowerBound, sizeof(double));
        munmap(sharedUpperBound, sizeof(double));
        munmap(sharedEC, sizeof(ErrorCode));
        return {ec, lower, upper};
    }
}
std::pair<ErrorCode, double> measureInSubprocess(std::list<LatMeasurement4> Measurements,
                                                 double Frequency, std::string Type) {
    // allocate memory to communicate result
    double *sharedResult = static_cast<double *>(
        mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ErrorCode *sharedEC = static_cast<ErrorCode *>(
        mmap(NULL, sizeof(ErrorCode), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));

    if (sharedResult == MAP_FAILED || sharedEC == MAP_FAILED) {
        perror("mmap");
        return {ERROR_MMAP, -1};
    }

    pid_t pid = fork();
    if (pid == -1) {
        return {ERROR_FORK, -1};
    }

    if (pid == 0) { // Child process
        ErrorCode ec;
        double res;
        if (Type == "t")
            dbg(__func__, "there is not tp measurement for LatMeasurement4");
        else
            std::tie(ec, res) = measureLatency4(Measurements, Frequency);

        *sharedResult = res;
        *sharedEC = ec;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) return {ERROR_GENERIC, -1};

        ErrorCode ec = *sharedEC;
        double res = *sharedResult;
        munmap(sharedResult, sizeof(int));
        munmap(sharedEC, sizeof(ErrorCode));
        return {ec, res};
    }
}

void displayProgress(int Progress, int Total) {
    int barWidth = 50;
    float ratio = Progress / (float)Total;
    int pos = barWidth * ratio;

    std::cerr << "\r[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos)
            std::cerr << "#";
        else if (i == pos)
            std::cerr << ">";
        else
            std::cerr << " ";
    }
    std::cerr << "] " << int(ratio * 100.0) << "% " << Progress << "/" << Total << std::flush;
}

int buildTPDatabase(double Frequency, unsigned MinOpcode, unsigned MaxOpcode) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    if (MaxOpcode == 0) MaxOpcode = env.MCII->getNumOpcodes();

    // measure TEST64rr and MOV64ri32 beforehand, because their tps are needed for interleaving
    // with other instructions
    if (env.Arch == Triple::ArchType::x86_64) {
        auto [EC, lowerTP, upperTP] =
            measureInSubprocess(env.getOpcode("TEST64rr"), Frequency, "t");
        throughputDatabase[env.getOpcode("TEST64rr")] = {EC, lowerTP, upperTP};
        priorityTPHelper.emplace_back(env.getOpcode("TEST64rr"));

        auto [EC2, lowerTP1, upperTP1] =
            measureInSubprocess(env.getOpcode("MOV64ri32"), Frequency, "t");
        throughputDatabase[env.getOpcode("MOV64ri32")] = {EC, lowerTP1, upperTP1};
        priorityTPHelper.emplace_back(env.getOpcode("MOV64ri32"));
    }

    bool gotNewMeasurement = true;
    while (gotNewMeasurement) {
        gotNewMeasurement = false;
        for (unsigned opcode = MinOpcode; opcode < MaxOpcode; opcode++) {
            // first check if this was already measured
            if (throughputDatabase.find(opcode) != throughputDatabase.end())
                if (throughputDatabase[opcode].ec != ERROR_NO_HELPER) continue;
            displayProgress(opcode, MaxOpcode);
            std::string name = env.MCII->getName(opcode).data();
            if (skipInstructions.find(name) != skipInstructions.end()) {
                out(*ios, name, ": skipped for reason\tskippedManually");
                continue;
            }

            auto [EC, lowerTP, upperTP] = measureInSubprocess(opcode, Frequency, "t");
            throughputDatabase[opcode] = {EC, lowerTP, upperTP};
            if (EC == SUCCESS) gotNewMeasurement = true;
        }
        errs() << "\n";
        errs().flush();
    }
    // print results
    for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
        std::string name = env.MCII->getName(opcode).data();
        name.resize(27, ' ');

        TPResult res = throughputDatabase[opcode];
        if (res.ec == SUCCESS) {
            std::printf("%s: %.3f-%.3f lower bound: %.3f (clock cycles)\n", name.data(),
                        res.lowerTP, res.upperTP, res.lowerTP);
            fflush(stdout);
        } else {
            outs() << name << ": " << "skipped for reason\t " << ecToString(res.ec) << "\n";
            outs().flush();
        }
    }
    return 0;
}

int buildLatDatabase(double Frequency, unsigned MinOpcode, unsigned MaxOpcode) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};

    std::unordered_set<unsigned> skipOpcodes;
    for (auto name : skipInstructions) {
        skipOpcodes.insert(env.getOpcode(name));
    }

    bool gotNewMeasurement = true;
    // rerun multiple times if more helper instructions are available now
    while (gotNewMeasurement) {
        gotNewMeasurement = false;
        for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
            displayProgress(opcode, MaxOpcode);
            if (errorCodeDatabase[opcode] != ERROR_NO_HELPER) continue;

            if (skipOpcodes.find(opcode) != skipOpcodes.end()) {
                errorCodeDatabase[opcode] = SKIP_MANUALLY;
                continue;
            }

            auto [EC, lat] = measureInSubprocess(opcode, Frequency, "l");
            errorCodeDatabase[opcode] = EC;
            latencyDatabase[opcode] = lat;
            if (EC == SUCCESS) gotNewMeasurement = true;
        }
    }
    // print results
    for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
        std::string name = env.MCII->getName(opcode).data();
        name.resize(27, ' ');

        if (errorCodeDatabase[opcode] == SUCCESS) {
            std::printf("%s: %.3f (clock cycles) Lat\n", name.data(), latencyDatabase[opcode]);
            fflush(stdout);
        } else {
            outs() << name << ": " << "skipped for reason\t "
                   << ecToString(errorCodeDatabase[opcode]) << "\n";
            outs().flush();
        }
    }
    return 0;
}

bool hasConnectionTo(std::vector<std::pair<unsigned, unsigned>> Values, unsigned First,
                     unsigned Second) {
    for (auto v : Values)
        if (v.first == First && v.second == Second) return true;

    return false;
}

std::vector<std::pair<unsigned, unsigned>>
findFullyConnected(std::vector<std::pair<unsigned, unsigned>> Edges, unsigned Number) {
    if (Number == 1 && !Edges.empty()) return {Edges[0]};
    if (Edges.size() != 0) dbg(__func__, "Edges: ", Edges);

    for (auto chosenEdge : Edges) {
        dbg(__func__, "chosen: ", chosenEdge.first, " ", chosenEdge.second);
        std::vector<std::pair<unsigned, unsigned>> edgesReduced;
        // for full connection the edges in the next recursion need to be between nodes which
        // both have a connection to the nodes of the chosen edge
        for (auto e : Edges) {
            if (e.first != chosenEdge.first && e.second != chosenEdge.second &&
                hasConnectionTo(Edges, e.first, chosenEdge.second) &&
                hasConnectionTo(Edges, chosenEdge.first, e.second))
                edgesReduced.emplace_back(e);
        }
        auto next = findFullyConnected(edgesReduced, Number - 1);
        if (!next.empty()) {
            next.emplace_back(chosenEdge);
            dbg(__func__, "good choice: ", chosenEdge.first, " ", chosenEdge.second);
            return next;
        }
        dbg(__func__, "bad choice: ", chosenEdge.first, " ", chosenEdge.second);
    }
    return {};
}

bool isVariant(unsigned A, unsigned B) {
    // check if a and b are the same instruction with different operands
    std::string nameA = env.MCII->getName(A).data();
    std::string nameB = env.MCII->getName(B).data();
    if (nameA == nameB) return true;
    // llvm names for the same instruction normally match until the first occurrence of a number
    // e.g. ADD8ri_EVEX ADD8ri_ND ADD8ri_NF ADD8ri_NF_ND
    auto getPrefixWithFirstNumber = [](const std::string &Name) -> std::string {
        size_t i = 0;
        // Find the start of the first number
        while (i < Name.size() && !isdigit(Name[i]))
            ++i;

        // include the whole number
        size_t j = i;
        while (j < Name.size() && isdigit(Name[j]))
            ++j;

        return Name.substr(0, j);
    };

    std::string namePrefixA = getPrefixWithFirstNumber(nameA);
    std::string namePrefixB = getPrefixWithFirstNumber(nameB);
    if (namePrefixA == namePrefixB) dbg(__func__, "found variant: ", nameA, " ", nameB);
    return namePrefixA == namePrefixB;
}

void findHelperInstructions(std::vector<LatMeasurement4> Measurements, double Frequency) {
    dbg(__func__, "number of measurements: ", Measurements.size());
    // classify measurements by operand combination
    std::map<DependencyType, std::vector<LatMeasurement4>> classifiedMeasurements;
    for (auto m : Measurements)
        classifiedMeasurements[m.type].emplace_back(m);

    for (auto classified : classifiedMeasurements)
        dbg(__func__, "class: ", classified.first);

    // to measure latencys of e.g. REG -> FLAGS we need some instruction (called helper
    // instruction) with known latency FLAGS -> REG so we can interleave the two. We determine
    // one such reference for each non trivial (non REG-> REG) latency operand to use in the
    // main benchmarking phase. holds a helper instruction for every LatencyOperand combination.
    std::map<DependencyType, LatMeasurement4> helperInstructions;
    std::set<DependencyType> noHelperPossible;
    for (auto [mType, typeA] : classifiedMeasurements) {
        if (helperInstructions.find(mType) != helperInstructions.end()) continue;
        if (noHelperPossible.find(mType) != noHelperPossible.end()) continue;
        if (mType.defOp == mType.useOp) {
            // trivial case
            for (auto m : typeA) {
                auto [EC, lat] = measureInSubprocess({m}, Frequency,
                                                     "l"); // TODO check if this is correct
                if (EC != 0 || lat < 2 || isSus(lat)) continue;
                // use first successful measurement as helper
                m.value = lat;
                helperInstructions.insert({mType, m});
                dbg(__func__, "found helper trivial: ", m);
                break;
            }
            continue;
        }
        // if (!(std::holds_alternative<MCRegister>(mType.useOp) &&
        //       std::get<MCRegister>(mType.useOp) == X86::EFLAGS)) {
        //     continue;
        // }

        dbg(__func__, "searching helper for type: ", mType);
        // std::vector<LatMeasurement4> typeA = classifiedMeasurements[typeA.first];
        std::vector<LatMeasurement4> typeB = classifiedMeasurements[mType.reversedType()];
        // We first want to find 3 instructions of the class and 3 of the reversed class to have
        // a total of 9 interleave combinations with *equal* and *minimal* combined latency >=2.
        // This is to make sure the instruction we select as helper really has the latency we
        // think. TODO explain better
        // :)

        // map: rounded latency -> list of measurementIndex pairs with that latency
        std::map<unsigned, std::vector<std::pair<unsigned, unsigned>>> values;
        std::map<unsigned, std::vector<std::pair<unsigned, unsigned>>> tempValues;
        // store instructions which cannot be measured (e.g. because they are not supported)
        std::set<unsigned> ignoredIndicesA;
        std::set<unsigned> ignoredIndicesB;

        std::vector<std::pair<unsigned, unsigned>> fullyConnected = {};
        unsigned indexA = 0, indexB = 0;
        unsigned helperLat = 0;
        // increment indexA and indexB once per iteration and measure all new combinations
        // possible. Then check if an instruction satisfies the conditions for a helper.
        while ((indexA < typeA.size() || indexB < typeB.size()) && fullyConnected.empty()) {
            if (indexA < typeA.size()) {
                // ignore variants of instructions already present
                bool ignored = false;
                for (unsigned i = 0; i < indexA; i++) {
                    if (isVariant(typeA[indexA].opcode, typeA[i].opcode)) {
                        ignoredIndicesA.insert(indexA);
                        indexA++;
                        ignored = true;
                        break;
                    }
                }
                if (ignored) continue;

                // add values for current indexA
                unsigned susCounter = 0;
                tempValues.clear();
                for (unsigned b = 0; b < indexB; b++) {
                    if (ignoredIndicesB.find(b) != ignoredIndicesB.end()) continue;
                    if (typeA[indexA].opcode == typeB[b].opcode)
                        continue; // dont interleave same instruction

                    dbg(__func__, "indices ", indexA, "/", typeA.size(), " ", b, "/", typeB.size());
                    auto [EC, combinedLat] =
                        measureInSubprocess({typeA[indexA], typeB[b]}, Frequency, "l");
                    // if unsuccessful, if sus or too small, add to ignored
                    if (EC != 0 || combinedLat < 2 || isSus(combinedLat)) {
                        susCounter++;
                        continue;
                    }
                    // insert measured value/2 (lat per operand)
                    tempValues[std::round(combinedLat / 2)].emplace_back(indexA, b);
                }
                if (susCounter > tempValues.size()) {
                    // this instruction behaved very unreliable, dont add it to potential
                    // helpers
                    dbg(__func__, indexB, " marked as sus");
                    ignoredIndicesA.insert(indexA);
                } else {
                    // move results into values
                    for (auto &[key, vec] : tempValues) {
                        auto &targetVec = values[key];
                        targetVec.insert(targetVec.end(), std::make_move_iterator(vec.begin()),
                                         std::make_move_iterator(vec.end()));
                    }
                }
                indexA++;
            }
            if (indexB < typeB.size()) {
                // ignore variants of instructions already present
                bool ignored = false;
                for (unsigned i = 0; i < indexB; i++) {
                    if (isVariant(typeB[indexB].opcode, typeB[i].opcode)) {
                        ignoredIndicesB.insert(indexA);
                        indexB++;
                        ignored = true;
                        break;
                    }
                }
                if (ignored) continue;

                // add values for fixed B
                unsigned susCounter = 0;
                tempValues.clear();
                for (unsigned a = 0; a < indexA; a++) {
                    if (ignoredIndicesA.find(a) != ignoredIndicesA.end()) continue;
                    if (typeA[a].opcode == typeB[indexB].opcode)
                        continue; // dont interleave same instruciton
                    dbg(__func__, "indices ", a, "/", typeA.size(), " ", indexB, "/", typeB.size());
                    auto [EC, combinedLat] =
                        measureInSubprocess({typeA[a], typeB[indexB]}, Frequency, "l");
                    // if unsuccessful, if sus or too small, add to ignored
                    if (EC != 0 || combinedLat < 2 || isSus(combinedLat)) {
                        susCounter++;
                        continue;
                    }
                    // insert measured value/2 (lat per operand)
                    tempValues[std::round(combinedLat / 2)].emplace_back(a, indexB);
                }
                if (susCounter > tempValues.size()) {
                    // this instruction behaved very unreliable, dont add it to potential
                    // helpers
                    dbg(__func__, indexB, " marked as sus");
                    ignoredIndicesB.insert(indexB);
                } else {
                    // move results into values
                    for (auto &[key, vec] : tempValues) {
                        auto &targetVec = values[key];
                        targetVec.insert(targetVec.end(), std::make_move_iterator(vec.begin()),
                                         std::make_move_iterator(vec.end()));
                    }
                }
                indexB++;
            }
            // check if new data is enough to determine two good helpers
            for (unsigned lat = 1; lat < 10; lat++) {
                // dbg(__func__, "checking if fully connected with numValues: ",
                // values[lat].size(),
                //     " for latency ", lat);
                if (values[lat].size() < 9) continue; // not possible with less than 9 edges
                fullyConnected = findFullyConnected(values[lat], 3);
                if (!fullyConnected.empty()) {
                    helperLat = lat;
                    dbg(__func__, "found fully connected with latency ", lat);
                    break;
                }
            }
        }
        if (fullyConnected.empty()) {
            // no helper for this type pair found, helpers are always found in pairs so opposite
            // direction will not be possible either
            dbg(__func__, "no helper for ", mType);
            noHelperPossible.insert(mType);
            noHelperPossible.insert(mType.reversedType());
            continue;
        }
        dbg(__func__, "after");
        // helper found, insert into helperInstructions
        auto measurementA = typeA[fullyConnected[0].first];
        auto measurementB = typeB[fullyConnected[0].second];
        measurementA.value = helperLat;
        measurementB.value = helperLat;
        helperInstructions.insert({measurementA.type, measurementA});
        helperInstructions.insert({measurementB.type, measurementB});
        dbg(__func__, "found a helper for ", measurementA.type);
        dbg(__func__, "found a helper for opposite type ", measurementB.type);
    }
    for (auto [mType, m] : classifiedMeasurements) {
        // LatMeasurement4 *inst = helperInstructions.find(mType);
        if (helperInstructions.find(mType) == helperInstructions.end()) {
            dbg(__func__, "no helper for ", mType, "searching for replacement");
            // until now for e.g. xmm1 -> class(GR64) only instructions of exactly this type
            // were considered, however if no suitable instructions were found we can use
            // instructions with class(VR128X) -> class(GR64) as well.
            std::set<Operand> replacementDefOperands;
            // insert the original operand to be used for new combination
            replacementDefOperands.insert(mType.defOp);

            // in case of a register, insert all reg classes this register belongs to
            if (mType.defOp.isRegister()) {
                auto reg = mType.defOp.getRegister();
                for (unsigned i = 0; i < env.MRI->getNumRegClasses(); i++)
                    if (env.regInRegClass(reg, i))
                        replacementDefOperands.insert(Operand::fromRegClass(i));
            }
            std::set<Operand> replacementUseOperands;
            replacementUseOperands.insert(mType.useOp);
            if (mType.useOp.isRegister()) {
                auto reg = mType.useOp.getRegister();
                for (unsigned i = 0; i < env.MRI->getNumRegClasses(); i++)
                    if (env.regInRegClass(reg, i))
                        replacementUseOperands.insert(Operand::fromRegClass(i));
            }

            // check if we have helpers for any combination of the replacement operands
            bool found = false;
            for (auto defOpType : replacementDefOperands) {
                for (auto useOpType : replacementUseOperands) {
                    DependencyType replacementType = DependencyType(defOpType, useOpType);
                    if (helperInstructions.find(replacementType) != helperInstructions.end()) {
                        // we have a helper for this type, use it for the current type
                        LatMeasurement4 m = helperInstructions.at(replacementType);
                        helperInstructions.insert({mType, m});
                        dbg(__func__, "using", m, "as replacement helper for ", mType);
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
            if (!found) dbg(__func__, "still no helper");

        } else {
            LatMeasurement4 m = helperInstructions.at(mType);
            dbg(__func__, "helper for ", mType, ":  ", m, " ", m.value);
        }
    }
    for (auto [mType, m] : helperInstructions) {
        std::string name = env.MCII->getName(m.opcode).str();
        name.resize(27, ' ');
        dbg(__func__, "helper for ", mType, ": ", m, " ", m.value);
    }
}

int buildLatDatabase4(double Frequency, unsigned MinOpcode, unsigned MaxOpcode) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};

    std::unordered_set<unsigned> skipOpcodes;
    for (auto name : skipInstructions) {
        skipOpcodes.insert(env.getOpcode(name));
    }

    // auto measurements = generator.genLatMeasurements();
    std::vector<LatMeasurement4> measurements =
        genLatMeasurements4(MinOpcode, MaxOpcode, skipOpcodes);
    findHelperInstructions(measurements, Frequency);
    // for (auto [mType, m] : helperInstructions) {
    //     dbg(__func__, "opcode", m.opcode);
    //     std::string name = env.MCII->getName(m.opcode).data();
    //     dbg(__func__, "helper: ", generator.latMeasurementTypeToString(mType), " ",
    //     name.data(),
    //         " ", m.value);
    // }
    // main benchmarking phase

    //     // unsigned indexA, indexB = 0;
    //     std::string currentIndex = "B";
    //     unsigned minLatency;
    //     std::vector<LatMeasurement> selectedA;
    //     std::vector<LatMeasurement> selectedB;
    //     while (true) {
    //         double latCombined = 1; // measure TODO
    //         if (equalWithTolerance(latCombined, minLatency)) {
    //             if (currentIndex == "A")
    //                 selectedA.emplace_back(typeA[indexA]);
    //             else
    //                 selectedB.emplace_back(typeA[indexB]);
    //         }
    //     }

    //     double targetLatency;
    //     for (unsigned maxTargetLatency = 1; maxTargetLatency < 10; maxTargetLatency++) {
    //         for (auto cur : typeA) {
    //             for (auto opp : typeB) {
    //                 // measure latency TODO
    //                 double combinedLat = 2.024;
    //                 // does meet target?
    //                 if (!smallerEqWithTolerance(combinedLat, maxTargetLatency * 2.0))
    //                     continue; // TODO cache result
    //                 // validate with other selected instructions
    //                 combinedLat = 1; // TODO
    //                 if (!equalWithTolerance(combinedLat, targetLatency))
    //                     selectedA.emplace_back(cur);
    //                 selectedB.emplace_back(opp);
    //                 if (selectedB.size() >= 3) break;
    //             }
    //             if (selectedA.size() >= 3) break;
    //         }
    //     }
    // }

    // bool gotNewMeasurement = true;
    // // rerun multiple times if more helper instructions are available now
    // while (gotNewMeasurement) {
    //     gotNewMeasurement = false;
    //     for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
    //         displayProgress(opcode, MaxOpcode);
    //         if (errorCodeDatabase[opcode] != ERROR_NO_HELPER) continue;

std::string generate_timestamped_filename(const std::string &prefix, const std::string &extension) {
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    // Format time
    std::ostringstream ss;
    ss << prefix << std::put_time(std::localtime(&now_c), "_%Y-%m-%d_%H-%M-%S") << extension;
    return ss.str();
}

void setOutputToFile(const std::string &filename) {
    fileStream = std::make_unique<std::ofstream>(filename);
    if (fileStream->is_open()) {
        ios = fileStream.get(); // Redirect global output
    } else {
        std::cerr << "Failed to open file: " << filename << std::endl;
        ios = &std::cout; // Fallback
    }
}

int main(int argc, char **argv) {
    struct option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"instruction", required_argument, nullptr, 'i'},
        {"opcode", required_argument, nullptr, 'o'},
        {"frequency", required_argument, nullptr, 'f'},
        {"cpu", required_argument, nullptr, 'c'},
        {"march", required_argument, nullptr, 'm'},
        {"minOpcode", required_argument, nullptr, 0},
        {"maxOpcode", required_argument, nullptr, 0},
        {nullptr, 0, nullptr, 0} // End marker
    };
    std::vector<std::string> instrNames;
    std::vector<unsigned> opcodes;
    double frequency = 3.75;
    int opt;
    std::string cpu = "";
    std::string march = "";
    unsigned minOpcode = 0;
    unsigned maxOpcode = 0;
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " {TP|LAT|INTERLEAVE|DEV} [options]\n";
        return 1;
    }
    enum Modes { TP, LAT, INTERLEAVE, DEV };
    std::string modeStr = argv[1];
    Modes mode;
    if (modeStr == "TP") {
        mode = TP;
    } else if (modeStr == "LAT") {
        mode = LAT;
    } else if (modeStr == "INTERLEAVE") {
        mode = INTERLEAVE;
    } else if (modeStr == "DEV") {
        mode = DEV;
    } else {
        std::cerr << "Unknown subprogram: " << mode << "\n";
        return 1;
    }

    int optionIndex = 0;
    argc -= 1; // Shift arguments
    argv += 1;
    while ((opt = getopt_long(argc, argv, "hi:f:m:o:", longOptions, &optionIndex)) != -1) {
        switch (opt) {
        case 0:
            if (strcmp(longOptions[optionIndex].name, "minOpcode") == 0)
                minOpcode = atoi(optarg);
            else if (strcmp(longOptions[optionIndex].name, "maxOpcode") == 0)
                maxOpcode = atoi(optarg);
            break;
        case 'h':
            std::cout << "Usage:" << argv[0]
                      << "[--help] [--instruction INST] [--frequency FREQ(GHz)] [--ninst nMax]\n";
            return 0;
        case 'i':
            instrNames.emplace_back(optarg);
            break;
        case 'o':
            opcodes.emplace_back(atoi(optarg));
            break;
        case 'f':
            frequency = atof(optarg);
            break;
        case 'm':
            march = optarg;
            break;
        case 'c':
            cpu = optarg;
            break;
        default:
            return 1;
        }
    }
    debug = false;
    dbgToFile = false;
    std::string filename = generate_timestamped_filename("run", ".log");
    setOutputToFile(filename);

    struct timeval start, end;
    gettimeofday(&start, NULL);
    // static LLVMEnvironment  env = LLVMEnvironment(march, cpu);
    ErrorCode ec = env.setUp(march, cpu);
    if (ec != SUCCESS) {
        outs() << "failed to set up environment: " << ecToString(ec) << "\n";
        return 1;
    }
    if (maxOpcode == 0) maxOpcode = env.MCII->getNumOpcodes();

    latencyDatabase.resize(maxOpcode, -1.0);
    errorCodeDatabase.resize(maxOpcode, ERROR_NO_HELPER);
    switch (mode) {
    case INTERLEAVE: {
        dbg(__func__, "no code in INTERLEAVE mode");
        break;
    }
    case TP: {
        out(*ios, "Mode: Throughput");
        if (instrNames.empty() && opcodes.empty()) {
            out(*ios, "No instructions specified, measuring all instructions from opcode ",
                minOpcode, " to ", maxOpcode);
            buildTPDatabase(frequency, minOpcode, maxOpcode);
            break;
        }
        dbgToFile = true;
        debug = true;
        // TODO release exclude from debug
        if (env.Arch == Triple::ArchType::x86_64) {
            // two common helpers for x86
            auto [EC, lower, upper] =
                measureInSubprocess(env.getOpcode("TEST64rr"), frequency, "t");
            if (EC == SUCCESS) {
                throughputDatabase[env.getOpcode("TEST64rr")] = {SUCCESS, lower, upper};
                priorityTPHelper.emplace_back(env.getOpcode("TEST64rr"));
            } else {
                dbg(__func__, "TEST64rr failed for reason: ", ecToString(EC));
                exit(1);
            }
            auto [EC2, lower2, upper2] =
                measureInSubprocess(env.getOpcode("MOV64ri32"), frequency, "t");
            if (EC2 == SUCCESS) {
                throughputDatabase[env.getOpcode("MOV64ri32")] = {SUCCESS, lower2, upper2};
                priorityTPHelper.emplace_back(env.getOpcode("MOV64ri32"));
            } else {
                dbg(__func__, "MOV64ri32 failed for reason: ", ecToString(EC));
                exit(1);
            }
        }
        for (unsigned opcode : opcodes) {
            auto [EC, lower, upper] = measureInSubprocess(opcode, frequency, "t");
            throughputDatabase[opcode] = {EC, lower, upper};
            if (EC != SUCCESS) {
                outs() << env.MCII->getName(opcode) << " failed for reason: " << ecToString(EC)
                       << "\n";
                outs().flush();
            } else {
                std::printf("%s: %.3f (clock cycles)\n", env.MCII->getName(opcode).data(), lower);
                fflush(stdout);
            }
        }
        for (auto instrName : instrNames) {
            int opcode = env.getOpcode(instrName.data());
            if (opcode == -1) outs() << "failed for reason: No instruction with this name " << "\n";
            auto [EC, lower, upper] = measureInSubprocess(opcode, frequency, "t");
            throughputDatabase[opcode] = {EC, lower, upper};
            if (EC != SUCCESS) {
                outs() << env.MCII->getName(opcode) << " failed for reason: " << ecToString(EC)
                       << "\n";
                outs().flush();
            } else {
                std::printf("%s: %.3f (clock cycles)\n", env.MCII->getName(opcode).data(), lower);
                fflush(stdout);
            }
        }
        break;
    }
    case LAT: {
        // example chain ADC16ri8 CMP16ri8
        // ADC32i32 PCMPESTRIrri CVTSI2SDrr TODO debug
        if (instrNames.empty()) {
            // buildLatDatabase(frequency, maxOpcode);
            debug = true;
            dbgToFile = true;
            buildLatDatabase4(frequency, maxOpcode);
            break;
        }
        dbgToFile = true;
        debug = true;
        for (auto instrName : instrNames) {
            unsigned opcode = env.getOpcode(instrName.data());

            auto [EC, lat] = measureInSubprocess(opcode, frequency, "l");
            if (EC != SUCCESS) {
                outs() << "failed for reason: " << ecToString(EC) << "\n";
                outs().flush();
            } else {
                std::printf("%.3f (clock cycles)\n", lat);
                fflush(stdout);
            }
            latencyDatabase[env.getOpcode(instrName)] = lat;
        }
        break;
    }
    case DEV: {
        dbg(__func__, "no code in DEV mode");
        break;
    }
    }
    gettimeofday(&end, NULL);
    auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    printf("total runtime: %f (s)\n", totalRuntime);
    std::cerr << " done\n";

    return 0;
}

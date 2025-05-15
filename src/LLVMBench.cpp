#include "LLVMBench.h"

#include "BenchmarkGenerator.h"              // for genInst4, isValid, whic...
#include "CustomDebug.h"                     // for dbg, debug
#include "ErrorCode.h"                       // for ErrorCode, ecToString
#include "Globals.h"                         // for LatMeasurement, Depend...
#include "LLVMEnvironment.h"                 // for LLVMEnvironment
#include "llvm/ADT/StringRef.h"              // for StringRef
#include "llvm/CodeGen/TargetRegisterInfo.h" // for TargetRegisterInfo
#include "llvm/MC/MCInst.h"                  // for MCInst, MCOperand
#include "llvm/MC/MCInstrDesc.h"             // for MCInstrDesc
#include "llvm/MC/MCInstrInfo.h"             // for MCInstrInfo
#include "llvm/MC/MCRegister.h"              // for MCRegister
#include "llvm/MC/MCRegisterInfo.h"          // for MCRegisterInfo
#include "llvm/MC/MCSubtargetInfo.h"         // for MCSubtargetInfo
#include "llvm/Support/raw_ostream.h"        // for raw_fd_ostream, raw_ost...
#include "llvm/TargetParser/Triple.h"        // for Triple
#include <algorithm>                         // for min_element, max
#include <chrono>                            // for system_clock
#include <csignal>                           // for SIGSEGV, size_t, SIGILL
#include <cstdio>                            // for printf, NULL, fflush
#include <cstdlib>                           // for exit, atoi, EXIT_SUCCESS
#include <ctime>                             // for localtime, time_t
#include <ctype.h>                           // for isdigit
#include <dlfcn.h>                           // for dlsym, dlclose, dlopen
#include <fcntl.h>                           // for open, O_WRONLY, O_TRUNC
#include <fstream>                           // for basic_ostream, operator<<
#include <getopt.h>                          // for required_argument, option
#include <iomanip>                           // for operator<<, put_time
#include <iostream>                          // for cerr, cout
#include <iterator>                          // for move_iterator, make_mov...
#include <map>                               // for map, operator!=, operat...
#include <memory>                            // for unique_ptr, make_unique
#include <sstream>                           // for basic_ostringstream
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

// #include "X86RegisterInfo.h"
// #include "MCTargetDesc/X86MCTargetDesc.h"
// #include "MCTargetDesc/X86BaseInfo.h"

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

namespace {
std::string generateTimestampedFilename(const std::string &Prefix, const std::string &Extension) {
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t nowC = std::chrono::system_clock::to_time_t(now);

    // Format time
    std::ostringstream ss;
    ss << Prefix << std::put_time(std::localtime(&nowC), "_%Y-%m-%d_%H-%M-%S") << Extension;
    return ss.str();
}

void setOutputToFile(const std::string &Filename) {
    fileStream = std::make_unique<std::ofstream>(Filename);
    if (fileStream->is_open()) {
        ios = fileStream.get(); // Redirect global output
    } else {
        std::cerr << "Failed to open file: " << Filename << std::endl;
        ios = &std::cout; // Fallback
    }
}

void displayProgress(size_t Progress, size_t Total) {
    int barWidth = 50;
    float ratio = (float)Progress / (float)Total;
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
} // namespace

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, int N, unsigned Runs) {
    dbg(__func__, "loopCount: ", N);
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
            fd = open("assembler_out.log", O_WRONLY | O_TRUNC | O_CREAT, 0644);
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
    void *handle = nullptr;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        return {ERROR_FILE, {}};
    }
    // get handles to function in the assembly file
    std::unordered_map<std::string, double (*)(int)> benchFunctionMap;
    std::unordered_map<std::string, double (*)()> initFunctionMap;
    for (std::string functionName : Assembly.getInitFunctionNames()) {
        auto functionPtr = (double (*)())dlsym(handle, functionName.data());
        if (functionPtr == NULL) {
            fprintf(stderr, "dlsym: couldn't find function %s\n", functionName.data());
            return {ERROR_GENERIC, {}};
        }
        initFunctionMap[functionName] = functionPtr;
    }
    for (std::string functionName : Assembly.getBenchFunctionNames()) {
        auto functionPtr = (double (*)(int))dlsym(handle, functionName.data());
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
    dbg(__func__, "benchmarks complete");

    dlclose(handle);
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
                                             unsigned NumInst, unsigned LoopCount, double Frequency,
                                             bool Throughput) {
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
    // Something strange is happening when measuring latencies. For some chains, e.g. Zen4
    // adc	al, 7
    // adc	cl, 7
    // ...
    // (chain on flags) the latency is smaller than expected (1.93 instead of 2) but increases with
    // unrolling. The loop overhead correction then corrects upwards which is not what was intended
    // but actually gives good results for now.
    // On the other hand for some instructions unrolling slightly decreases throughput e.g. ADC16ri8
    // with helper TEST64rr In those cases the unrolled time should not be used for correction.
    // This is why the following check is only enabled for throughput
    if (Throughput && instRuntime * 2 > UnrolledRuntime) {
        cyclesPerInstruction = (Runtime / 1e6) * (Frequency * 1e9) / (NumInst * LoopCount);
    }
    return {SUCCESS, cyclesPerInstruction};
}

std::tuple<ErrorCode, int, std::map<unsigned, MCRegister>> getTPHelperInstruction(unsigned Opcode) {
    // first check if this instruction needs a helper
    // generate two instructions and check for dependencys
    std::set<MCRegister> usedRegs;
    auto [ec1, inst1] = genInst(Opcode, {}, usedRegs);
    auto [ec2, inst2] = genInst(Opcode, {}, usedRegs);
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
    dbg(__func__, "checking size ", priorityTPHelper.size());
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
                auto [ec1, inst] = genInst(Opcode, {}, tmpUsedRegs);
                auto [ec2, helperInst] = genInst(possibleHelper, helperConstraints, tmpUsedRegs);
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
            auto [ec1, inst] = genInst(Opcode, {}, tmpUsedRegs);
            auto [ec2, helperInst] = genInst(possibleHelper, helperConstraints, tmpUsedRegs);
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

    auto [ec1, helperOpcode, helperConstraints] = getTPHelperInstruction(Opcode);
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

    auto [EC, correctedTP] = calculateCycles(time1, time2, numInst, n, Frequency, true);
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

std::pair<ErrorCode, double> measureLatency(const std::list<LatMeasurement> &Measurements,
                                            unsigned LoopCount, double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    double n = LoopCount;
    ErrorCode ec;
    ErrorCode warning = NO_ERROR_CODE;
    AssemblyFile assembly;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(ec, assembly) = genLatBenchmark(Measurements, &numInst1);
    if (ec != SUCCESS && ec != WARNING_MULTIPLE_DEPENDENCIES) return {ec, -1};
    if (ec == WARNING_MULTIPLE_DEPENDENCIES) warning = WARNING_MULTIPLE_DEPENDENCIES;
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1};

    // take minimum of runs. "latency" and "latencyUnrolled" is naming convention defined in
    // runBenchmark()
    double time1 =
        *std::min_element(benchResults["latency"].begin(), benchResults["latency"].end());
    double time2 = *std::min_element(benchResults["latencyUnrolled"].begin(),
                                     benchResults["latencyUnrolled"].end());
    double cycles;
    std::tie(ec, cycles) = calculateCycles(time1, time2, numInst1, n, Frequency, false);
    if (ec != SUCCESS) {
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
    if (warning != NO_ERROR_CODE) return {warning, cycles};
    return {SUCCESS, cycles};
}

std::tuple<ErrorCode, double, double> measureInSubprocess(unsigned Opcode, double Frequency) {
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

        std::tie(ec, lower, upper) = measureThroughput(Opcode, Frequency);

        *sharedLowerBound = lower;
        *sharedUpperBound = upper;
        *sharedEC = ec;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);
        dbg(__func__, "child exited on status ", status);

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

std::pair<ErrorCode, double> measureInSubprocess(const std::list<LatMeasurement> &Measurements,
                                                 unsigned LoopCount, double Frequency) {
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
        std::tie(ec, res) = measureLatency(Measurements, LoopCount, Frequency);

        *sharedResult = res;
        *sharedEC = ec;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);
        dbg(__func__, "child exited on status ", status);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGILL) return {ILLEGAL_INSTRUCTION, -1};
        if (WIFSIGNALED(status)) return {ERROR_SIGNAL, -1};
        if (WEXITSTATUS(status) != EXIT_SUCCESS) return {ERROR_GENERIC, -1};

        ErrorCode ec = *sharedEC;
        double res = *sharedResult;
        munmap(sharedResult, sizeof(int));
        munmap(sharedEC, sizeof(ErrorCode));
        return {ec, res};
    }
}

int buildTPDatabase(double Frequency, unsigned MinOpcode, unsigned MaxOpcode) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    if (MaxOpcode == 0) MaxOpcode = env.MCII->getNumOpcodes();

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

            auto [EC, lowerTP, upperTP] = measureInSubprocess(opcode, Frequency);
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
            // select lower bound for print except it is close or equal to 0
            double selected = res.lowerTP;
            if (selected < 0.2) selected = res.upperTP;
            std::printf("%s: %.3f-%.3f selected: %.3f (clock cycles)\n", name.data(), res.lowerTP,
                        res.upperTP, res.lowerTP);
            fflush(stdout);
        } else {
            outs() << name << ": " << "skipped for reason\t " << ecToString(res.ec) << "\n";
            outs().flush();
        }
    }
    return 0;
}

bool isVariant(unsigned A, unsigned B) {

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

// run small test to check if execution results in ILLEGAL_INSTRUCTION or fails in any other way
ErrorCode canMeasure(LatMeasurement Measurement, double Frequency) {
    auto [EC, lat] = measureInSubprocess({Measurement}, 2, Frequency);
    if (!isError(EC)) return SUCCESS;
    return EC;
}

void buildLatDatabase(double Frequency) {
    out(*ios, "number of measurements: ", latencyDatabase.size());
    // opcodes which cannot be measured as (e.g. because they are not supported on the platform)
    std::set<unsigned> opcodeBlacklist;
    std::set<DependencyType> completedTypes;

    // classify measurements by operand combination, measure if trivial
    errs() << "phase1: trivial measurements\n";
    size_t progress = 0;
    std::map<DependencyType, std::vector<LatMeasurement>> classifiedMeasurements;
    for (auto measurement : latencyDatabase) {
        displayProgress(progress++, latencyDatabase.size());
        if (measurement.type.isSymmetric()) {
            auto [EC, lat] = measureInSubprocess({measurement}, 1e6, Frequency);
            measurement.ec = EC;
            measurement.lowerBound = lat;
            measurement.upperBound = lat;
            if (EC == WARNING_MULTIPLE_DEPENDENCIES)
                out(*ios, "---", measurement, "---\n",
                    "WARNING generated instructions have multiple dependencies between each "
                    "other. If they have different latencys the lower one will be shadowed");
            classifiedMeasurements[measurement.type].emplace_back(measurement);
            completedTypes.insert(measurement.type); // blacklist symmetric for phase 2
            if (EC == ILLEGAL_INSTRUCTION) opcodeBlacklist.emplace(measurement.opcode);
        } else if (canMeasure(measurement, Frequency) == SUCCESS)
            // needs helper to be measured, classify but dont measure yet
            classifiedMeasurements[measurement.type].emplace_back(measurement);
    }

    // now iterate over all pairs A, B of dependencyTypes where A.reversed() == B and do the
    // measurements of those types
    // e.g. if A is GR16 -> EFLAGS, B is EFLAGS -> GR16 and we can measure combinations of
    // instructions in A and B
    errs() << "\nphase2: measurements with helpers\n";
    progress = 0;
    for (auto &[dTypeA, measurementsA] : classifiedMeasurements) {
        displayProgress(progress++, classifiedMeasurements.size());
        if (completedTypes.find(dTypeA) != completedTypes.end()) continue;

        DependencyType dTypeB = dTypeA.reversed();
        completedTypes.insert(dTypeA);
        completedTypes.insert(dTypeB);
        out(*ios, "-----", dTypeA, " and ", dTypeB, "-----");
        out(*ios, measurementsA.size(), " measurements of first Type");
        // check if there are measurements for dTypeB
        if (classifiedMeasurements.find(dTypeB) == classifiedMeasurements.end()) {
            out(*ios, "no measurements of type ", dTypeB, " so ", dTypeA,
                " can also not be measured");
            for (auto &mA : measurementsA)
                mA.ec = ERROR_NO_HELPER;
            continue;
        }
        auto &measurementsB = classifiedMeasurements[dTypeB];
        out(*ios, measurementsB.size(), " measurements of reversed Type");
        // from now on, if the errorCode doesnt get set by measuring the instructions it is because
        // there is no helper. Set all error codes to ERROR_NO_HELPER here to avoid duplicate code
        for (auto &mA : measurementsA)
            mA.ec = ERROR_NO_HELPER;
        for (auto &mB : measurementsB)
            mB.ec = ERROR_NO_HELPER;

        // find the pair of instructions that has the smallest combined latency. then use those
        // two
        // instructions to measure all other. This way the resulting ranges are as small as posible
        double minCombinedLat = 1000;
        // select first A which can be measured
        LatMeasurement &smallestA = measurementsA[0];
        for (auto &mA : measurementsA) {
            if (opcodeBlacklist.find(mA.opcode) != opcodeBlacklist.end()) continue;
            smallestA = mA;
            break;
        }
        // check if there is any valid A
        if (opcodeBlacklist.find(smallestA.opcode) != opcodeBlacklist.end()) {
            out(*ios, "no measurement of type ", dTypeA, " can be executed successfully");
            continue;
        }

        // find smallest B
        LatMeasurement &smallestB = measurementsB[0];
        for (LatMeasurement &mB : measurementsB) {
            if (opcodeBlacklist.find(mB.opcode) != opcodeBlacklist.end()) continue;
            if (mB.opcode == smallestA.opcode) continue;
            auto [EC, lat] = measureInSubprocess({smallestA, mB}, 1e6, Frequency);
            dbg(__func__, "measured ", lat, " from ", mB, " and ", smallestA);
            if (EC != SUCCESS) {
                if (EC == WARNING_MULTIPLE_DEPENDENCIES) {
                    out(*ios, "Detected multiple dependencys between the interleaved instructions. "
                              "This will not be considered for finding helpers");
                } else {
                    out(*ios, "measuring ", smallestA, " and ", mB,
                        " was unsuccessful, EC: ", ecToString(EC),
                        " this is unusual because both were executed individually before");
                }
                continue;
            }
            if (isUnusualLat(lat)) {
                out(*ios, "unusual ", lat, " from ", mB, " and ", smallestA);
                continue;
            }
            if (lat < minCombinedLat) {
                smallestB = mB;
                minCombinedLat = lat;
            }
            // optimization: there is nothing better than two instructions with latency 1 cy
            if (minCombinedLat == 2) break;
        }
        // check if there is any valid B
        if (opcodeBlacklist.find(smallestB.opcode) != opcodeBlacklist.end()) {
            out(*ios, "no measurement of type ", dTypeB, " can be executed successfully");
            continue;
        }

        // we have the smallest measurement of type B, measure all of type A and keep track of
        // the one with the smallest latency
        for (LatMeasurement &mA : measurementsA) {
            if (opcodeBlacklist.find(mA.opcode) != opcodeBlacklist.end()) continue;
            if (mA.opcode == smallestB.opcode) continue;
            auto [EC, lat] = measureInSubprocess({mA, smallestB}, 1e6, Frequency);
            dbg(__func__, "measured ", lat, " from ", mA, " and ", smallestB);
            if (EC != SUCCESS) {
                if (EC == WARNING_MULTIPLE_DEPENDENCIES) {
                    out(*ios, "Detected multiple dependencys between the interleaved instructions. "
                              "This will not be considered for finding helpers");
                } else {
                    out(*ios, "measuring ", mA, " and ", smallestB,
                        " was unsuccessful, EC: ", ecToString(EC),
                        " this is unusual because both were executed individually before");
                }
                continue;
            }
            if (isUnusualLat(lat)) {
                out(*ios, "unusual ", lat, " from ", mA, " and ", smallestB);
                continue;
            }
            if (lat < minCombinedLat) {
                smallestA = mA;
                minCombinedLat = lat;
            }
            // optimization: there is nothing better than two instructions with latency 1 cy
            if (minCombinedLat == 2) break;
        }
        if (isUnusualLat(minCombinedLat) || minCombinedLat < 2) {
            out(*ios, "can not find a pair with normal latency for types");
            continue;
        }

        smallestA.lowerBound = 1;
        smallestA.upperBound = minCombinedLat - 1;
        smallestB.lowerBound = 1;
        smallestB.upperBound = minCombinedLat - 1;
        // we now have the two measurements with the lowest combined latency
        // use them to measure everything else
        for (LatMeasurement &mA : measurementsA) {
            if (opcodeBlacklist.find(mA.opcode) != opcodeBlacklist.end()) continue;
            if (mA.opcode == smallestB.opcode) continue;
            auto [EC, lat] = measureInSubprocess({mA, smallestB}, 1e6, Frequency);
            mA.ec = EC;
            mA.lowerBound = lat - smallestB.upperBound;
            mA.upperBound = lat - smallestB.lowerBound;
            if (EC == SUCCESS) {
                out(*ios, "---", mA, "---");
                out(*ios, "\tDependencies: ", smallestA, ", ", smallestB);
                out(*ios, "\tCombined: ", lat, " cycles");
            }
        }
        for (LatMeasurement &mB : measurementsB) {
            if (opcodeBlacklist.find(mB.opcode) != opcodeBlacklist.end()) continue;
            if (mB.opcode == smallestA.opcode) continue;
            auto [EC, lat] = measureInSubprocess({smallestA, mB}, 1e6, Frequency);
            mB.ec = EC;
            mB.lowerBound = lat - smallestA.upperBound;
            mB.upperBound = lat - smallestA.lowerBound;
            if (EC == SUCCESS) {
                out(*ios, "---", mB, "---");
                out(*ios, "\tDependencies: ", smallestA, ", ", smallestB);
                out(*ios, "\tCombined: ", lat, " cycles");
            }
        }
    }

    // print results
    for (auto &[dTypeA, measurementsA] : classifiedMeasurements) {
        for (LatMeasurement &measurement : measurementsA) {
            std::string name = env.MCII->getName(measurement.opcode).data();
            name.resize(27, ' ');

            std::ostringstream ss;
            ss << measurement;
            if (!isError(measurement.ec)) {
                std::printf("%s\n", ss.str().data());
                fflush(stdout);
            } else {
                outs() << ss.str().data() << " " << "skipped for reason\t "
                       << ecToString(measurement.ec) << "\n";
                outs().flush();
            }
        }
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
    double frequency;
    int opt;
    std::string cpu = "";
    std::string march = "";
    unsigned minOpcode = 0;
    unsigned maxOpcode = 0;
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " {TP|LAT|INTERLEAVE|DEV} [options]\n";
        return 1;
    }
    std::string filename = generateTimestampedFilename("run", ".log");
    setOutputToFile(filename);

    enum Modes { TP, LAT, INTERLEAVE, DEV };
    std::string modeStr = argv[1];
    Modes mode;
    if (modeStr == "TP") {
        mode = TP;
        out(*ios, "Mode: Throughput");
    } else if (modeStr == "LAT") {
        mode = LAT;
        out(*ios, "Mode: Latency");
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
    out(*ios, "Frequency: ", frequency, " GHz");
    debug = false;
    dbgToFile = false;

    struct timeval start, end;
    gettimeofday(&start, NULL);
    // static LLVMEnvironment  env = LLVMEnvironment(march, cpu);
    ErrorCode ec = env.setUp(march, cpu);
    if (ec != SUCCESS) {
        std::cerr << "failed to set up environment: " << ecToString(ec) << "\n";
        return 1;
    }
    out(*ios, "Arch: ", env.MSTI->getCPU().str());
    if (maxOpcode == 0) maxOpcode = env.MCII->getNumOpcodes();

    for (auto instrName : instrNames) {
        unsigned opcode = env.getOpcode(instrName.data());
        if (opcode == std::numeric_limits<unsigned>::max()) {
            std::cerr << "No instruction with name \"" << instrName << "\"\n";
            exit(1);
        }
        opcodes.emplace_back(opcode);
    }

    switch (mode) {
    case INTERLEAVE: {
        dbg(__func__, "no code in INTERLEAVE mode");
        break;
    }
    case TP: {
        // measure TEST64rr and MOV64ri32 beforehand, because their tps are needed for interleaving
        // with other instructions
        if (env.Arch == Triple::ArchType::x86_64) {
            auto [EC, lowerTP, upperTP] = measureInSubprocess(env.getOpcode("TEST64rr"), frequency);
            throughputDatabase[env.getOpcode("TEST64rr")] = {EC, lowerTP, upperTP};
            priorityTPHelper.emplace_back(env.getOpcode("TEST64rr"));

            auto [EC2, lowerTP1, upperTP1] =
                measureInSubprocess(env.getOpcode("MOV64ri32"), frequency);
            throughputDatabase[env.getOpcode("MOV64ri32")] = {EC, lowerTP1, upperTP1};
            priorityTPHelper.emplace_back(env.getOpcode("MOV64ri32"));
        }
        if (instrNames.empty() && opcodes.empty()) {
            out(*ios, "No instructions specified, measuring all instructions from opcode ",
                minOpcode, " to ", maxOpcode);
            buildTPDatabase(frequency, minOpcode, maxOpcode);
            break;
        }
        dbgToFile = true;
        debug = true;
        for (unsigned opcode : opcodes) {
            auto [EC, lower, upper] = measureInSubprocess(opcode, frequency);
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
        // skip instructions which take long and are irrelevant
        std::set<std::string> skipInstructions = {
            "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r",
            "RDSEED16r", "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",
            "SLDT64r",   "SMSW16r",   "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",
            "STR64r",    "VERRr",     "VERWr"};

        std::unordered_set<unsigned> skipOpcodes;
        for (auto name : skipInstructions) {
            skipOpcodes.insert(env.getOpcode(name));
        }

        // example chain ADC16ri8 CMP16ri8
        // ADC32i32 PCMPESTRIrri CVTSI2SDrr TODO debug
        if (instrNames.empty() && opcodes.empty()) {
            // debug = true;
            out(*ios, "No instructions specified, measuring all instructions from opcode ",
                minOpcode, " to ", maxOpcode);
            debug = true; // TODO remove
            latencyDatabase = genLatMeasurements(minOpcode, maxOpcode, skipOpcodes);
            buildLatDatabase(frequency);
            break;
        }
        dbgToFile = true;
        debug = true;

        for (auto opcode : opcodes) {
            auto measurements = genLatMeasurements(opcode, opcode + 1, {});
            latencyDatabase.insert(latencyDatabase.begin(), measurements.begin(),
                                   measurements.end());
        }
        buildLatDatabase(frequency);
        break;
    }
    case DEV: {
        dbg(__func__, "no code in DEV mode");
        break;
    }
    }
    gettimeofday(&end, NULL);
    auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    out(*ios, "total runtime: ", totalRuntime, " (s)");
    std::cerr << " done\n";

    return 0;
}

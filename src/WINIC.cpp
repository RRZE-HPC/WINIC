#include "WINIC.h"

#include "BenchmarkGenerator.h"
#include "CLI11.hpp"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include "IOSystem.h"
#include "LLVMEnvironment.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/TargetParser/Triple.h"
#include <AssemblyFile.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <tuple>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// #include "X86RegisterInfo.h"
// #include "MCTargetDesc/X86MCTargetDesc.h"
// #include "MCTargetDesc/X86BaseInfo.h"

namespace llvm {
class MCInstrDesc;
}

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

namespace {
std::string generateTimestamp() {
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t nowC = std::chrono::system_clock::to_time_t(now);

    // Format time
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&nowC), "%Y-%m-%d_%H-%M-%S");
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
    if (!showProgress) return;
    int barWidth = 50;
    float ratio = (float)Progress / (float)Total;
    int pos = barWidth * ratio;

    std::cout << "\r[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos)
            std::cout << "#";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << int(ratio * 100.0) << "% " << Progress << "/" << Total << std::flush;
}

// create ./asm and clear all existing files
void prepAsmDir() {
    namespace fs = std::filesystem;

    std::string asmDir = (fs::current_path() / "asm").string();
    if (!fs::exists(asmDir)) {
        if (!fs::create_directories(asmDir)) {
            std::cerr << "Failed to create directory: " << asmDir << std::endl;
            return;
        }
    }
    for (const auto &entry : fs::directory_iterator(asmDir)) {
        fs::remove_all(entry.path());
    }
}
} // namespace

std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, unsigned N, unsigned Runs) {
    dbg(__func__, "N: ", N, " Runs: ", Runs);
    std::string clangPath = CLANG_PATH;
    if (clangPath == "usr/bin/clang") {
        std::cerr << "CLANG_PATH not set, using default" << std::endl;
    }
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return {E_FILE, {}};
    }
    asmFile << Assembly.generateAssembly();
    asmFile.close();
    if (dbgToFile) {
        std::string debugPath =
            std::filesystem::current_path().string() + "/asm/" + Assembly.getName() + ".s";
        std::ofstream debugFile(debugPath);
        if (!debugFile) {
            std::cerr << "Failed to create debug file at " << debugPath.data() << std::endl;
        } else {
            debugFile << Assembly.generateAssembly();
            debugFile.close();
        }
    }
    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    // "gcc -x assembler-with-cpp -shared -mfp16-format=ieee " + sPath + " -o " + oPath + " 2>
    // gcc_out";

    // slightly worse performance than fork
    //  std::string compiler = CLANG_PATH;
    //  std::string command = compiler + " -x assembler-with-cpp -shared " + sPath + " -o " +
    // oPath;
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
        std::string extraOptions = "";
        if (getEnv().Arch == llvm::Triple::riscv64) extraOptions += "-march=rv64gcv";

        execl(CLANG_PATH, "clang", extraOptions.data(), "-x", "assembler-with-cpp", "-shared",
              sPath.data(), "-o", oPath.data(), nullptr);
        _exit(127);       // execl failed
    } else if (pid > 0) { // Parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            if (WEXITSTATUS(status) == 127) return {E_EXEC, {}};
            return {E_ASSEMBLY, {}};
        }
    }

    // from ibench
    void *handle = nullptr;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        std::cerr << "dlopen: failed to open .so file" << std::endl;
        return {E_FILE, {}};
    }
    // get handles to function in the assembly file
    std::unordered_map<std::string, double (*)(int)> benchFunctionMap;
    std::unordered_map<std::string, double (*)()> initFunctionMap;
    for (std::string functionName : Assembly.getInitFunctionNames()) {
        auto functionPtr = (double (*)())dlsym(handle, functionName.data());
        if (functionPtr == NULL) {
            std::cerr << "dlsym: couldn't find function " << functionName.data() << std::endl;
            return {E_GENERIC, {}};
        }
        initFunctionMap[functionName] = functionPtr;
    }
    for (std::string functionName : Assembly.getBenchFunctionNames()) {
        auto functionPtr = (double (*)(int))dlsym(handle, functionName.data());
        if (functionPtr == NULL) {
            std::cerr << "dlsym: couldn't find function " << functionName.data() << std::endl;
            return {E_GENERIC, {}};
        }
        benchFunctionMap[functionName] = functionPtr;
    }
    // may have results from prior runs
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

    dlclose(handle);
    return {SUCCESS, benchtimes};
}

std::pair<ErrorCode, std::vector<double>> runManual(std::string SPath, unsigned Runs,
                                                    unsigned NumInst, int LoopCount,
                                                    double Frequency, std::string FunctionName,
                                                    std::string InitName) {
    dbg(__func__, "SPath: ", SPath, " Runs: ", Runs, " NumInst: ", NumInst,
        " LoopCount: ", LoopCount, " Frequency: ", Frequency, " FunctionName: ", FunctionName,
        " InitName: ", InitName);
    std::string clangPath = CLANG_PATH;
    std::string oPath = "/dev/shm/temp.so";
    std::string extraOptions = "";
    if (getEnv().Arch == llvm::Triple::riscv64) extraOptions += "-march=rv64gcv";
    std::string command = clangPath + " " + extraOptions.data() +
                          " -x assembler-with-cpp -shared " + SPath + " -o " + oPath +
                          " 2> assembler_out.log";
    if (system(command.data()) != 0) return {E_ASSEMBLY, {}};

    // from ibench
    void *handle;
    double (*function)(int);
    double (*init)() = nullptr;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        std::cerr << "dlopen: failed to open .so file" << std::endl;
        return {E_ASSEMBLY, {}};
    }
    if (!InitName.empty()) {
        if ((init = (double (*)())dlsym(handle, InitName.data())) == NULL) {
            std::cerr << "dlsym: couldn't find function " << InitName << std::endl;
            return {E_GENERIC, {}};
        }
    }
    if ((function = (double (*)(int))dlsym(handle, FunctionName.data())) == NULL) {
        std::cerr << "dlsym: couldn't find function " << FunctionName << std::endl;
        return {E_GENERIC, {}};
    }
    struct timeval start, end;
    std::vector<double> benchtimes;
    for (unsigned i = 0; i < Runs; i++) {
        if (init) (*init)();
        gettimeofday(&start, NULL);
        // actual call to benchmarked function
        (*function)(LoopCount);
        gettimeofday(&end, NULL);
        benchtimes.insert(benchtimes.end(),
                          (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
    }

    dlclose(handle);
    return {SUCCESS, benchtimes};
}

std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                             unsigned NumInst, unsigned LoopCount, double Frequency,
                                             bool Throughput) {
    dbg(__func__, "Runtime: ", Runtime, " UnrolledRuntime: ", UnrolledRuntime,
        " NumInst: ", NumInst, " LoopCount: ", LoopCount);
    // correct the result using one measurement with NumInst and one with 2*NumInst. This
    // removes overhead of e.g. the loop instructions themselves see README for explanation TODO
    double instRuntime = UnrolledRuntime - Runtime;
    // runtime[usec -> sec] * Frequency[GHz -> Hz] / number of instructions executed
    double cyclesPerInstruction = (instRuntime / 1e6) * (Frequency * 1e9) / (NumInst * LoopCount);
    if (instRuntime * 2 > UnrolledRuntime * 1.1) {
        // Execution time increases overproportional when unrolling, which should not happen.
        // This is unlikely to be a good measurement, report an error and let the user measure it
        // manually.
        return {E_UNROLL_ANOMALY, -1};
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

std::tuple<ErrorCode, unsigned, std::map<unsigned, MCRegister>>
getTPHelperInstruction(unsigned Opcode) {
    dbg(__func__, "Opcode: ", Opcode);
    // first check if this instruction needs a helper
    // generate two instructions and check for dependencys
    std::set<MCRegister> usedRegs;
    auto [ec1, inst1] = genInst(Opcode, {}, usedRegs);
    auto [ec2, inst2] = genInst(Opcode, {}, usedRegs);
    std::list<DependencyType> dependencies = getDependencies(inst1, inst2);
    if (dependencies.empty()) return {SUCCESS, MAX_UNSIGNED, {}}; // no helper needed
    if (dependencies.size() > 1) {
        dbg(__func__, "multiple dependencies");
        // this instruction has multiple dependencies on itself, this
        // is currently not supported
        return {E_NO_HELPER, MAX_UNSIGNED, {}};
    }
    // this instruction will always have one dependency on itself. We have to break this by
    // interleaving another instruction. The other instruction has to:
    // 1. be measured already
    // 2. define the used register of the dependency
    // 3. not be dependent on the current instruction
    auto dep = dependencies.front();
    auto useReg = dep.useOp.getRegister();

    unsigned helperOpcode = MAX_UNSIGNED;
    std::map<unsigned, MCRegister> helperConstraints;
    // first we try opcodes in the priorityTPHelper list. Those are allowed to be used as helper
    // even if they write not to the register itself but a superregister
    // on Zen4 there is a partial write penalty when writing to just a part of a GPR
    // priorityTPHelper can be used to prevent this from happening
    for (unsigned possibleHelper : priorityTPHelper) {
        TPMeasurement tpRes = throughputDatabase[possibleHelper];
        if (tpRes.ec != SUCCESS) continue;                          // no value
        if (!greaterEqWithTolerance(tpRes.lowerTP, 0.25)) continue; // we dont trust values this low
        for (MCRegister possibleWriteReg : getEnv().getPossibleDefs(possibleHelper)) {
            if (getEnv().TRI->isSuperRegisterEq(useReg, possibleWriteReg)) {
                useReg = possibleWriteReg;
                auto [EC, opIndex] = whichOperandCanUse(possibleHelper, "def", useReg);
                // we checked the instruction is able to define the register
                if (EC != SUCCESS) return {E_UNREACHABLE, MAX_UNSIGNED, {}};
                if (opIndex != -1)
                    helperConstraints.insert({(unsigned)opIndex, useReg});
                else {
                    // whichOperandCanUse returned -1 so the required register is defined
                    // implicitly and we don't need to constrain the helper instruction
                }
                // check 3. generate a pair of instructions to check for unwanted dependencies
                // this will catch implicit dependencies e.g. instruction writes to EFLAGS and
                // helper reads EFLAGS
                // explicit dependencies e.g. ADD16ri can define ax but if it does it also uses
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
    if (helperOpcode != MAX_UNSIGNED) return {SUCCESS, helperOpcode, helperConstraints};
    dbg(__func__, "no prio helper");
    // the no priorityHelper can be used, try all other instructions now
    for (auto [possibleHelper, res] : throughputDatabase) {
        if (res.ec != SUCCESS) continue;
        if (greaterEqWithTolerance(res.lowerTP, 0.25)) continue;
        std::set<MCRegister> possibleWrites = getEnv().getPossibleDefs(possibleHelper);
        if (possibleWrites.find(useReg) != possibleWrites.end()) {
            auto [EC, opIndex] = whichOperandCanUse(possibleHelper, "def", useReg);
            if (EC != SUCCESS) return {E_UNREACHABLE, MAX_UNSIGNED, {}};
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
    if (helperOpcode == MAX_UNSIGNED) return {E_NO_HELPER, MAX_UNSIGNED, {}};
    return {SUCCESS, helperOpcode, helperConstraints};
}

std::tuple<ErrorCode, double, double> measureThroughput(unsigned Opcode, double Frequency) {
    dbg(__func__, "Opcode: ", Opcode, " Frequency: ", Frequency);
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst = 12;
    unsigned n = 1000000; // loop count
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
    assembly.setName(getEnv().MCII->getName(Opcode).str());
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1, -1};

    // take minimum of runs (naming convention of funcitons in genTPBenchmark)
    double time1 = *std::min_element(benchResults["tp"].begin(), benchResults["tp"].end());
    double time2 = *std::min_element(benchResults["tp2"].begin(), benchResults["tp2"].end());

    auto [EC, correctedTP] = calculateCycles(time1, time2, numInst, n, Frequency, true);
    if (helperOpcode != MAX_UNSIGNED) {
        // we did use a helper, this can change the TP
        // TODO change once port distribution is implemented
        throughputOutputMessage[Opcode] +=
            str("\tHelper: ", throughputDatabase[helperOpcode], "\n");
        throughputOutputMessage[Opcode] += str("\tCombined result: ", correctedTP, "\n");

        double tpSamePorts = correctedTP - throughputDatabase[helperOpcode].lowerTP;
        if (tpSamePorts < 1 / 4) {
            throughputOutputMessage[Opcode] +=
                str("\tAssuming instruction and helper use different ports, otherwise TP would be ",
                    tpSamePorts, "\n");
            return {SUCCESS, correctedTP, correctedTP};
        }
        throughputOutputMessage[Opcode] +=
            str("\tNo hints if instruction and helper use same ports, TP can be in range ",
                tpSamePorts, " - ", correctedTP, "\n");
        return {SUCCESS, tpSamePorts, correctedTP};
    }
    return {SUCCESS, correctedTP, correctedTP};
}

std::pair<ErrorCode, double> measureLatency(const std::list<LatMeasurement> &Measurements,
                                            unsigned LoopCount, double Frequency) {
    dbg(__func__, "Measurements.size(): ", Measurements.size(), " LoopCount: ", LoopCount,
        " Frequency: ", Frequency);

    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    unsigned n = LoopCount;
    ErrorCode ec;
    ErrorCode warning = NO_ERROR_CODE;
    AssemblyFile assembly;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(ec, assembly) = genLatBenchmark(Measurements, &numInst1);
    if (ec != SUCCESS && ec != W_MULTIPLE_DEPENDENCIES) return {ec, -1};
    if (ec == W_MULTIPLE_DEPENDENCIES) warning = W_MULTIPLE_DEPENDENCIES;
    assembly.setName(Measurements.front().toCompactString());
    std::tie(ec, benchResults) = runBenchmark(assembly, n, 3);
    if (ec != SUCCESS) return {ec, -1};

    // take minimum of runs. "lat" and "lat2" is naming convention defined in
    // runBenchmark()
    double time1 = *std::min_element(benchResults["lat"].begin(), benchResults["lat"].end());
    double time2 = *std::min_element(benchResults["lat2"].begin(), benchResults["lat2"].end());
    double cycles;
    std::tie(ec, cycles) = calculateCycles(time1, time2, numInst1, n, Frequency, false);
    if (ec != SUCCESS) {
        std::string chainString = "";
        for (auto m : Measurements) {
            chainString += getEnv().MCII->getName(m.opcode).data();
            chainString += " -> ";
        }
        for (auto time : benchResults["lat2"]) {
            chainString += std::to_string(time) + " ";
        }
        dbg(__func__, "anomaly detected during measurement: ", chainString.data());
        return {E_GENERIC, -1};
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
    char *sharedMessage = static_cast<char *>(
        mmap(NULL, 300, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));

    if (sharedUpperBound == MAP_FAILED || sharedLowerBound == MAP_FAILED ||
        sharedEC == MAP_FAILED || sharedMessage == MAP_FAILED) {
        perror("mmap");
        return {E_MMAP, -1, -1};
    }

    pid_t pid = fork();
    if (pid == -1) return {E_FORK, -1, -1};

    if (pid == 0) { // Child process
        ErrorCode ec;
        double lower;
        double upper;
        std::tie(ec, lower, upper) = measureThroughput(Opcode, Frequency);

        *sharedLowerBound = lower;
        *sharedUpperBound = upper;
        *sharedEC = ec;
        strncpy(sharedMessage, throughputOutputMessage[Opcode].data(), 299);
        sharedMessage[299] = '\0';
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            munmap(sharedEC, sizeof(ErrorCode));
            munmap(sharedLowerBound, sizeof(double));
            munmap(sharedUpperBound, sizeof(double));
            munmap(sharedMessage, 300);
            if (WTERMSIG(status) == SIGSEGV) return {E_SIGSEGV, -1, -1};
            if (WTERMSIG(status) == SIGILL) return {E_ILLEGAL_INSTRUCTION, -1, -1};
            return {E_SIGNAL, -1, -1};
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS)
            return {E_UNREACHABLE, -1, -1};

        ErrorCode ec = *sharedEC;
        double lower = *sharedLowerBound;
        double upper = *sharedUpperBound;
        throughputOutputMessage[Opcode] = std::string(sharedMessage);
        munmap(sharedEC, sizeof(ErrorCode));
        munmap(sharedLowerBound, sizeof(double));
        munmap(sharedUpperBound, sizeof(double));
        munmap(sharedMessage, 300);
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
        return {E_MMAP, -1};
    }

    pid_t pid = fork();
    if (pid == -1) return {E_FORK, -1};

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

        if (WIFSIGNALED(status)) {
            munmap(sharedResult, sizeof(double));
            munmap(sharedEC, sizeof(ErrorCode));
            if (WTERMSIG(status) == SIGSEGV) return {E_SIGSEGV, {}};
            if (WTERMSIG(status) == SIGILL) return {E_ILLEGAL_INSTRUCTION, {}};
            return {E_SIGNAL, {}};
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) return {E_UNREACHABLE, {}};

        ErrorCode ec = *sharedEC;
        double res = *sharedResult;
        munmap(sharedResult, sizeof(double));
        munmap(sharedEC, sizeof(ErrorCode));
        return {ec, res};
    }
}

std::pair<ErrorCode, std::vector<double>>
measureInSubprocess(std::string SPath, unsigned Runs, unsigned NumInst, unsigned LoopCount,
                    double Frequency, std::string FunctionName, std::string InitName) {
    // allocate memory to communicate result
    double *sharedResults = static_cast<double *>(mmap(
        NULL, Runs * sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ErrorCode *sharedEC = static_cast<ErrorCode *>(
        mmap(NULL, sizeof(ErrorCode), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));

    if (sharedResults == MAP_FAILED || sharedEC == MAP_FAILED) {
        perror("mmap");
        return {E_MMAP, {}};
    }

    pid_t pid = fork();
    if (pid == -1) return {E_FORK, {}};

    if (pid == 0) { // Child process
        ErrorCode EC;
        std::vector<double> res;
        std::tie(EC, res) =
            runManual(SPath, Runs, NumInst, LoopCount, Frequency, FunctionName, InitName);
        *sharedEC = EC;
        for (unsigned i = 0; i < res.size() && i < Runs; i++)
            sharedResults[i] = res[i];

        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            munmap(sharedResults, Runs * sizeof(double));
            munmap(sharedEC, sizeof(ErrorCode));
            if (WTERMSIG(status) == SIGSEGV) return {E_SIGSEGV, {}};
            if (WTERMSIG(status) == SIGILL) return {E_ILLEGAL_INSTRUCTION, {}};
            return {E_SIGNAL, {}};
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) return {E_UNREACHABLE, {}};

        ErrorCode EC = *sharedEC;
        std::vector<double> res;
        for (unsigned i = 0; i < Runs; i++)
            res.push_back(sharedResults[i]);

        munmap(sharedResults, Runs * sizeof(double));
        munmap(sharedEC, sizeof(ErrorCode));
        return {EC, res};
    }
}

bool isVariant(unsigned A, unsigned B) {
    std::string nameA = getEnv().MCII->getName(A).data();
    std::string nameB = getEnv().MCII->getName(B).data();
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
    return namePrefixA == namePrefixB;
}

// run small test to check if execution results in ILLEGAL_INSTRUCTION or fails in any other way
ErrorCode canMeasure(LatMeasurement Measurement, double Frequency) {
    auto [EC, lat] = measureInSubprocess({Measurement}, 2, Frequency);
    if (!isError(EC)) return SUCCESS;
    return EC;
}

void buildTPDatabase(std::vector<unsigned> Opcodes, double Frequency) {
    // mark instructions to be measured
    for (unsigned opcode : Opcodes)
        throughputDatabase[opcode].ec = NO_ERROR_CODE;

    bool gotNewMeasurement = true;
    while (gotNewMeasurement) {
        gotNewMeasurement = false;
        size_t progress = 0;
        for (unsigned opcode : Opcodes) {
            displayProgress(progress++, Opcodes.size());
            // check if this was already measured
            if (throughputDatabase.find(opcode) != throughputDatabase.end())
                if (throughputDatabase[opcode].ec != E_NO_HELPER &&
                    throughputDatabase[opcode].ec != NO_ERROR_CODE)
                    continue;
            // check if this opcode can be measured
            const MCInstrDesc &desc = getEnv().MCII->get(opcode);
            ErrorCode ec = isValid(desc);
            if (isValid(desc) != SUCCESS) {
                throughputDatabase[opcode] = {opcode, ec, -1, -1};
                continue;
            }
            auto [EC, lowerTP, upperTP] = measureInSubprocess(opcode, Frequency);
            throughputDatabase[opcode] = {opcode, EC, lowerTP, upperTP};
            throughputOutputMessage[opcode] += str("\t", throughputDatabase[opcode], "\n");

            if (EC == SUCCESS) gotNewMeasurement = true;
        }
        std::cerr << std::endl;
    }
    for (auto entry : throughputOutputMessage) {
        out(*ios, "-----", getEnv().MCII->getName(entry.first).data(), "-----");
        out(*ios, entry.second);
    }
}

void buildLatDatabase(double Frequency) {
    dbg(__func__, "Frequency: ", Frequency);
    out(*ios, "Number of measurements: ", latencyDatabase.size());
    // opcodes which cannot be measured as (e.g. because they are not supported on the platform)
    std::set<unsigned> opcodeBlacklist;
    std::set<DependencyType> completedTypes;

    // classify measurements by operand combination, measure if trivial
    if (showProgress) std::cout << "phase1: trivial measurements\n";
    size_t progress = 0;
    std::map<DependencyType, std::vector<LatMeasurement *>> classifiedMeasurements;
    for (auto &measurement : latencyDatabase) {
        displayProgress(progress++, latencyDatabase.size());
        if (measurement.type.isSymmetric()) {
            // symmetric means the operand read and written to are of the same type.
            // e.g. GR16 -> GR16. Those can build a latency chain on their own
            auto [EC, lat] = measureInSubprocess({measurement}, 1e6, Frequency);
            measurement.ec = EC;
            measurement.lowerBound = lat;
            measurement.upperBound = lat;
            classifiedMeasurements[measurement.type].emplace_back(&measurement);
            completedTypes.insert(measurement.type); // blacklist symmetric for phase 2
            if (EC == SUCCESS) {
                latencyOutputMessage[measurement.opcode] +=
                    str("\t", measurement.toStringWithBounds(), "\n\t\t Successful, latency: ", lat,
                        "\n");
            } else if (EC == W_MULTIPLE_DEPENDENCIES)
                latencyOutputMessage[measurement.opcode] +=
                    str("\t", measurement.toStringWithBounds(),
                        "\n\t\tWARNING generated instructions have multiple dependencies. "
                        "If they have different latencies the lower one will be shadowed\n");
            else if (isError(EC)) {
                latencyOutputMessage[measurement.opcode] +=
                    str("\t", measurement.toStringWithBounds(), "\n\t\t", ecToString(EC),
                        ", this instruction cannot be measured on this platform\n");
                opcodeBlacklist.emplace(measurement.opcode);
            }
        } else {
            // This is not symmetric, it can only be measured in pair with another instruction
            // which has the same dependencyType but reversed. e.g. GR16 -> EFLAGS and EFLAGS ->
            // GR16 Run quick test to see if this instruction can be measured this is done here
            // because later instructions get measured in pairs and it is not clear which one caused
            // the problem
            ErrorCode EC = canMeasure(measurement, Frequency);
            if (EC == SUCCESS)
                // needs helper to be measured, classify but dont measure yet
                classifiedMeasurements[measurement.type].emplace_back(&measurement);
            else {
                measurement.ec = EC;
                latencyOutputMessage[measurement.opcode] +=
                    str("\t", measurement, "\n\t\t", ecToString(EC),
                        ", this instruction cannot be measured on this platform\n");
            }
        }
    }

    // now iterate over all pairs A, B of dependencyTypes where A.reversed() == B and do the
    // measurements of those types
    // e.g. if A is GR16 -> EFLAGS, B is EFLAGS -> GR16 and we can measure combinations of
    // instructions in A and B
    if (showProgress) std::cout << "\nphase2: measurements with helpers\n";
    out(*ios, "\n\nReport on finding helpers for dependency types:");
    progress = 0;
    for (auto &[dTypeA, measurementsA] : classifiedMeasurements) {
        displayProgress(progress++, classifiedMeasurements.size());
        if (completedTypes.find(dTypeA) != completedTypes.end()) continue;

        DependencyType dTypeB = dTypeA.reversed();
        completedTypes.insert(dTypeA);
        completedTypes.insert(dTypeB);
        out(*ios, "-----", dTypeA, " and ", dTypeB, "-----");
        out(*ios, "\t", measurementsA.size(), " measurements of first Type");
        // Check if there are measurements for dTypeB
        if (classifiedMeasurements.find(dTypeB) == classifiedMeasurements.end()) {
            out(*ios, "\tno measurements of type ", dTypeB, " so ", dTypeA,
                " can also not be measured");
            for (auto &mA : measurementsA)
                mA->ec = E_NO_HELPER;
            continue;
        }
        auto &measurementsB = classifiedMeasurements[dTypeB];
        out(*ios, "\t", measurementsB.size(), " measurements of reversed Type");
        // From now on, if the errorCode doesnt get set by measuring the instructions, it is because
        // there is no helper. Set all error codes to ERROR_NO_HELPER here to avoid duplicate code
        for (auto &mA : measurementsA)
            mA->ec = E_NO_HELPER;
        for (auto &mB : measurementsB)
            mB->ec = E_NO_HELPER;

        // Find the pair of instructions of the current types that has the smallest combined
        // latency. Then use those two instructions to measure all other. This way the resulting
        // ranges are as small as posible
        double minCombinedLat = 1000;
        // Select first A which can be measured
        LatMeasurement *smallestA = measurementsA[0];
        for (auto &mA : measurementsA) {
            if (opcodeBlacklist.find(mA->opcode) != opcodeBlacklist.end()) continue;
            smallestA = mA;
            break;
        }
        // Check if there is any valid A
        if (opcodeBlacklist.find(smallestA->opcode) != opcodeBlacklist.end()) {
            out(*ios, "\tno measurement of type ", dTypeA, " can be executed successfully");
            continue;
        }
        out(*ios, "\tSelecting helper instructions for this type combination");

        // Find smallest B
        LatMeasurement *smallestB = measurementsB[0];
        for (LatMeasurement *mB : measurementsB) {
            if (opcodeBlacklist.find(mB->opcode) != opcodeBlacklist.end()) continue;
            if (mB->opcode == smallestA->opcode) continue;
            out(*ios, "\tMeasuring ", *smallestA, " and ", *mB);
            auto [EC, lat] = measureInSubprocess({*smallestA, *mB}, 1e6, Frequency);
            if (EC != SUCCESS) {
                if (EC == W_MULTIPLE_DEPENDENCIES) {
                    out(*ios, "\tDetected multiple dependencys between ", *smallestA, " and ", *mB,
                        "so result of their combination will not be considered for finding "
                        "helpers");
                } else {
                    out(*ios, "\tMeasuring ", *smallestA, " and ", *mB,
                        " was unsuccessful, EC: ", ecToString(EC),
                        ". this is unusual because both were executed individually before");
                }
                continue;
            }
            if (isUnusualLat(lat)) {
                out(*ios, "\tUnusual latency: ", lat, " from ", *mB, " and ", *smallestA,
                    "discarding this result");
                continue;
            }
            if (lat < minCombinedLat) {
                smallestB = mB;
                minCombinedLat = lat;
            }
            // optimization: there is nothing better than two instructions with latency 1 cy
            if (equalWithTolerance(minCombinedLat, 2)) break;
        }
        // Check if a valid B was found
        if (opcodeBlacklist.find(smallestB->opcode) != opcodeBlacklist.end()) {
            out(*ios, "No measurement of type ", dTypeB, " can be executed successfully");
            continue;
        }

        // Find smallest A
        for (LatMeasurement *mA : measurementsA) {
            if (opcodeBlacklist.find(mA->opcode) != opcodeBlacklist.end()) continue;
            if (mA->opcode == smallestB->opcode) continue;
            auto [EC, lat] = measureInSubprocess({*mA, *smallestB}, 1e6, Frequency);
            if (EC != SUCCESS) {
                if (EC == W_MULTIPLE_DEPENDENCIES) {
                    out(*ios, "\tDetected multiple dependencys between ", *mA, " and ", *smallestB,
                        "so result of their combination will not be considered for finding "
                        "helpers");
                } else {
                    out(*ios, "\tMeasuring ", *mA, " and ", *smallestB,
                        " was unsuccessful, EC: ", ecToString(EC),
                        " this is unusual because both were executed individually before");
                }
                continue;
            }
            if (isUnusualLat(lat)) {
                out(*ios, "\tUnusual ", lat, " from ", *mA, " and ", *smallestB,
                    "discarding this result");
                continue;
            }
            if (lat < minCombinedLat) {
                smallestA = mA;
                minCombinedLat = lat;
            }
            // Optimization: there is nothing better than two instructions with latency 1 cy
            if (equalWithTolerance(minCombinedLat, 2)) break;
        }
        if (isUnusualLat(minCombinedLat) || minCombinedLat < 2) {
            out(*ios, "\tCan not find a pair with normal latency for types");
            continue;
        }

        smallestA->lowerBound = 1;
        smallestA->upperBound = minCombinedLat - 1;
        smallestB->lowerBound = 1;
        smallestB->upperBound = minCombinedLat - 1;
        out(*ios, "\tFound helper instructions ", *smallestA, " and ", *smallestB,
            " with combined latency ", minCombinedLat);
        // smallestA and smallestB now are the measurements with the lowest combined latency
        // Use them to measure everything else
        for (LatMeasurement *mA : measurementsA) {
            if (opcodeBlacklist.find(mA->opcode) != opcodeBlacklist.end()) continue;
            if (mA->opcode == smallestB->opcode) continue;
            auto [EC, lat] = measureInSubprocess({*mA, *smallestB}, 1e6, Frequency);
            mA->ec = EC;
            mA->lowerBound = lat - smallestB->upperBound;
            mA->upperBound = lat - smallestB->lowerBound;
            latencyOutputMessage[mA->opcode] += str("\t", mA->toStringWithBounds(), "\n");
            if (!isError(EC)) {
                latencyOutputMessage[mA->opcode] +=
                    str("\t\tDependencies:\n\t\t\t", *smallestA, "\n\t\t\t", *smallestB, "\n");
                latencyOutputMessage[mA->opcode] += str("\t\tCombined result: ", lat, " cycles\n");
            }
        }
        for (LatMeasurement *mB : measurementsB) {
            if (opcodeBlacklist.find(mB->opcode) != opcodeBlacklist.end()) continue;
            if (mB->opcode == smallestA->opcode) continue;
            auto [EC, lat] = measureInSubprocess({*smallestA, *mB}, 1e6, Frequency);
            mB->ec = EC;
            mB->lowerBound = lat - smallestA->upperBound;
            mB->upperBound = lat - smallestA->lowerBound;
            if (isUnusualLat(mB->lowerBound)) mB->ec = E_UNUSUAL_LATENCY;

            latencyOutputMessage[mB->opcode] += str("\t", mB->toStringWithBounds(), "\n");
            if (!isError(EC)) {
                latencyOutputMessage[mB->opcode] +=
                    str("\t\tDependencies:\n\t\t\t", *smallestA, "\n\t\t\t", *smallestB, "\n");
                latencyOutputMessage[mB->opcode] += str("\t\tCombined result: ", lat, " cycles\n");
            }
        }
    }

    // Print report strings collected
    out(*ios, "\n\nReport on individual measurements:");
    for (auto entry : latencyOutputMessage) {
        out(*ios, "-----", getEnv().MCII->getName(entry.first).data(), "-----");
        out(*ios, entry.second);
    }
}

int main(int argc, char **argv) {
    double frequency;
    std::string cpu = "";
    std::string march = "";
    CLI::App app{"winic"};
    app.add_option("-f,--frequency", frequency, "Frequency in GHz")->required();
    app.add_flag("-d,--debug", debug, "Enable debug output")->default_val(false);
    // not tested, used in case llvm cant detect platform
    app.add_option("-c,--cpu", cpu, "CPU model");
    app.add_option("-m,--march", march, "Architecture");

    std::vector<std::string> instrNames;
    unsigned minOpcode = 0;
    unsigned maxOpcode = 0;
    bool noReport = false;
    std::string databasePath = "";
    auto *tp = app.add_subcommand("TP", "Throughput");
    auto *tpInstOpt = tp->add_option("-i,--instruction", instrNames, "LLVM Instruction names");
    tp->add_option("--minOpcode", minOpcode, "Minimum opcode to measure")->excludes(tpInstOpt);
    tp->add_option("--maxOpcode", maxOpcode, "Maximum opcode to measure")->excludes(tpInstOpt);
    tp->add_flag("--noReport", noReport, "Don't generate report file")->default_val(false);
    tp->add_option("-o,--output", databasePath,
                   "Path to the .yaml file to save the results to. If the file already exists new "
                   "values will be overwritten. If emtpy a timestamped file will be generated. If "
                   "/dev/null no file will be generated");
    tp->add_flag("--X87FP", includeX87FP, "Include x87 floating point instructions")
        ->default_val(false);

    auto *lat = app.add_subcommand("LAT", "Latency");
    auto *latInstOpt = lat->add_option("-i,--instruction", instrNames, "LLVM Instruction names");
    lat->add_option("--minOpcode", minOpcode, "Minimum opcode to measure")->excludes(latInstOpt);
    lat->add_option("--maxOpcode", maxOpcode, "Maximum opcode to measure")->excludes(latInstOpt);
    lat->add_flag("--noReport", noReport, "Don't generate report file")->default_val(false);
    lat->add_option("-o,--output", databasePath,
                    "Path to the .yaml file to save the results to. If the file already exists new "
                    "values will be overwritten. If emtpy a timestamped file will be generated. If "
                    "/dev/null no file will be generated");
    lat->add_flag("--X87FP", includeX87FP, "Include x87 floating point instructions")
        ->default_val(false);

    std::string sPath, funcName, initName = "";
    unsigned numInst;
    auto *man = app.add_subcommand("MAN", "Manual");
    man->add_option("-p,--path", sPath, "Assembly file path")->required()->check(CLI::ExistingPath);
    man->add_option("--funcName", funcName, "Function to benchmark")->required();
    man->add_option("-n,--nInst", numInst, "Number of instructions in loop")->required();
    man->add_option("--initName", initName, "Initialization function");

    app.require_subcommand(1, 1);
    CLI11_PARSE(app, argc, argv)

    // configure output
    std::cout.precision(3);
    ios->precision(3);
    std::string timestamp = generateTimestamp();

    if (noReport || *man)
        setOutputToFile("/dev/null");
    else if (*tp)
        setOutputToFile("report_TP_" + timestamp + ".txt");
    else if (*lat)
        setOutputToFile("report_LAT_" + timestamp + ".txt");

    if (databasePath != "/dev/null") {
        if (databasePath.empty()) databasePath = str("db_", timestamp, ".yaml");
        if (std::filesystem::exists(databasePath)) {
            out(*ios, "Using existing database: ", databasePath);
            ErrorCode EC = loadYaml(databasePath);
            if (EC != SUCCESS) return -1;
        } else
            out(*ios, "Creating new database: ", databasePath);
    }

    std::ostringstream ss;
    for (int i = 0; i < argc; ++i)
        ss << argv[i] << " ";

    out(*ios, "Command: ", ss.str());
    out(*ios, "Frequency: ", frequency, " GHz");
    dbgToFile = false;

    struct timeval start, end;
    gettimeofday(&start, NULL);
    ErrorCode ec = getEnv().setUp(march, cpu);
    if (ec != SUCCESS) {
        std::cerr << "failed to set up environment: " << ecToString(ec) << std::endl;
        return 1;
    }
    out(*ios, "Arch: ", getEnv().MSTI->getCPU().str());
    if (maxOpcode == 0) maxOpcode = getEnv().MCII->getNumOpcodes();

    std::vector<unsigned> opcodes;
    for (auto instrName : instrNames) {
        unsigned opcode = getEnv().getOpcode(instrName.data());
        if (opcode == std::numeric_limits<unsigned>::max()) {
            std::cerr << "No instruction with name \"" << instrName << "\"" << std::endl;
            exit(1);
        }
        opcodes.emplace_back(opcode);
    }

    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions;
    std::unordered_set<unsigned> opcodeBlacklist;

    if (getEnv().Arch == Triple::ArchType::x86_64) {
        skipInstructions = {"SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r",
                            "RDRAND64r", "RDSEED16r", "RDSEED32r", "RDSEED64r", "RDTSC",
                            "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",   "SMSW32r",
                            "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",
                            "VERWr"};
    }
    for (auto name : skipInstructions)
        opcodeBlacklist.insert(getEnv().getOpcode(name));

    if (*tp) {
        out(*ios, "Mode: Throughput");
        if (getEnv().Arch == Triple::ArchType::x86_64) {
            // measure TEST64rr and MOV64ri32 beforehand, because their tps are needed for
            // interleaving with other instructions
            unsigned opcodeTest = getEnv().getOpcode("TEST64rr");
            auto [EC, lowerTP, upperTP] = measureInSubprocess(opcodeTest, frequency);
            throughputDatabase[opcodeTest] = {opcodeTest, EC, lowerTP, upperTP};
            priorityTPHelper.emplace_back(opcodeTest);

            unsigned opcodeMov = getEnv().getOpcode("MOV64ri32");
            auto [EC2, lowerTP1, upperTP1] = measureInSubprocess(opcodeMov, frequency);
            throughputDatabase[opcodeMov] = {opcodeMov, EC2, lowerTP1, upperTP1};
            priorityTPHelper.emplace_back(opcodeMov);
        }
        if (opcodes.empty()) {
            out(*ios, "No instructions specified, measuring all instructions from opcode ",
                minOpcode, " to ", maxOpcode);
            for (unsigned opcode = minOpcode; opcode < maxOpcode; opcode++) {
                // skip instructions which are not supported on this platform
                if (opcodeBlacklist.find(opcode) != opcodeBlacklist.end()) {
                    throughputDatabase[opcode].ec = S_MANUALLY;
                    continue;
                }
                opcodes.emplace_back(opcode);
            }

            buildTPDatabase(opcodes, frequency);
        } else {
            showProgress = false;
            dbgToFile = true;

            prepAsmDir();
            buildTPDatabase(opcodes, frequency);
            for (auto opcode : opcodes) {
                if (throughputDatabase.find(opcode) == throughputDatabase.end())
                    continue; // should not happen
                std::cout << str(throughputDatabase[opcode]) << std::endl;
            }
        }
        // update output database with new values
        for (auto &[opcode, result] : throughputDatabase)
            if (result.ec == SUCCESS) updateDatabaseEntryTP(result);

        // save database
        if (databasePath != "/dev/null") {
            ErrorCode EC = saveYaml(databasePath);
            if (EC != SUCCESS) return 1;
        }
    } else if (*lat) {
        out(*ios, "Mode: Latency");

        // example chain ADC16ri8 CMP16ri8
        // ADC32i32 PCMPESTRIrri CVTSI2SDrr TODO debug
        if (opcodes.empty()) {
            out(*ios, "No instructions specified, measuring all instructions from opcode ",
                minOpcode, " to ", maxOpcode);
            latencyDatabase = genLatMeasurements(minOpcode, maxOpcode, opcodeBlacklist);
            buildLatDatabase(frequency);
        } else {
            showProgress = false;
            dbgToFile = true;
            prepAsmDir();
            for (auto opcode : opcodes) {
                auto measurements = genLatMeasurements(opcode, opcode + 1, {});
                latencyDatabase.insert(latencyDatabase.begin(), measurements.begin(),
                                       measurements.end());
            }
            buildLatDatabase(frequency);
            for (auto m : latencyDatabase) {
                if (std::find(opcodes.begin(), opcodes.end(), m.opcode) == opcodes.end())
                    continue; // skip prio helpers
                std::cout << m.toStringWithBounds() << std::endl;
            }
        }
        // update database with new values
        for (LatMeasurement result : latencyDatabase) {
            ErrorCode EC = updateDatabaseEntryLAT(result);
            if (EC != SUCCESS) {
                std::string msg =
                    str("failed to update database entry for ", result, ": ", ecToString(EC));
                out(*ios, msg);
                std::cerr << msg << std::endl;
            }
        }

        // save database
        if (databasePath != "/dev/null") {
            ErrorCode EC = saveYaml(databasePath);
            if (EC != SUCCESS) return 1;
        }
    } else if (*man) {
        auto [EC, times] =
            measureInSubprocess(sPath, 3, numInst, 1e6, frequency, funcName, initName);
        if (EC != SUCCESS) {
            std::cout << "failed for reason: " << ecToString(EC) << "\n";
            return 1;
        }
        for (auto time : times) {
            std::cout << time << " ";
        }
        double minTime = *std::min_element(times.begin(), times.end());
        std::cout << " min: " << minTime << "\n";

        // runtime[usec -> sec] * Frequency[GHz -> Hz] / number of instructions executed
        double cyclesPerInstruction = (minTime / 1e6) * (frequency * 1e9) / (numInst * 1e6);
        std::cout << cyclesPerInstruction << " (clock cycles)\n";
    }

    gettimeofday(&end, NULL);
    auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    out(*ios, "total runtime: ", totalRuntime, " (s)");
    std::cout << " done" << std::endl;

    return 0;
}

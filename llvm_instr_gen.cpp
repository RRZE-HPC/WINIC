// #include "MCTargetDesc/X86MCTargetDesc.h"
// #include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "benchmarkGenerator.cpp"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegister.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TypeSize.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
#include <bits/getopt_core.h>
#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <math.h>
#include <ostream>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#ifndef CLANG_PATH
#define CLANG_PATH "usr/bin/clang"
#endif

// #include "llvm/Support/FileSystem.h"
// #include "llvm/MC/MCObjectWriter.h"
// #include "llvm/CodeGen/MachineRegisterInfo.h"
// #include "llvm/lib/Target/X86/X86RegisterInfo.h"
// #include <llvm/include/llvm/ADT/StringRef.h>
// #include "llvm/MC/MCAsmInfo.h"
// #include "llvm/MC/MCTargetOptions.h"
// #include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/Support/raw_ostream.h"
// #include "llvm/MC/MCDisassembler/MCDisassembler.h"

static std::unordered_map<unsigned, float> throughputDatabase;
static std::vector<float> latencyDatabase;
static std::vector<ErrorCode> errorCodeDatabase;
static std::list<std::tuple<unsigned, std::set<MCRegister>, std::set<MCRegister>>>
    helperInstructions; // opcode, read/write register
using namespace llvm;
// using dbg = BenchmarkGenerator::dbg;
static bool dbgToFile = true;

// Global jump buffer for recovery from illegal instruction
static sigjmp_buf jumpBuffer;
static volatile sig_atomic_t lastSignal = 0;
void *globalHandle = nullptr;

// Signal handler for illegal instruction
static void signalHandler(int Signum) {
    // shared library handle is not closed when segfaulting in benchmark
    if (globalHandle) {
        dlclose(globalHandle); // Cleanup
        globalHandle = nullptr;
        dbg(__func__, "dlclose called\n");
    }
    lastSignal = Signum;
    siglongjmp(jumpBuffer, 1); // Jump back to safe point
}

static std::pair<ErrorCode, std::unordered_map<std::string, std::list<double>>>
runBenchmark(AssemblyFile Assembly, int N, unsigned Runs) {
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
        std::string DebugPath =
            "/home/hpc/ihpc/ihpc149h/bachelor/llvm-project/build/own_tools/llvm-bench/debug.s";
        std::ofstream debugFile(DebugPath);
        if (!debugFile) {
            std::cerr << "Failed to create debug file" << std::endl;
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
        if (dbgToFile) {
            int fd = open("assembler_out.log", O_WRONLY);
            if (fd == -1) {
                perror("open assembler_out.log failed");
                _exit(127);
            }
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            execl(CLANG_PATH, "clang", "-x", "assembler-with-cpp", "-shared", sPath.data(), "-o",
                  oPath.data(), nullptr);
        } else {
            int fd = open("/dev/null", O_WRONLY);
            if (fd == -1) {
                perror("open /dev/null failed");
                _exit(127);
            }
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            execl(CLANG_PATH, "clang", "-x", "assembler-with-cpp", "-shared", sPath.data(), "-o",
                  oPath.data(), nullptr);
        }
        _exit(127);       // execlp failed
    } else if (pid > 0) { // Parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            if (WEXITSTATUS(status) == 127) return {ERROR_EXEC, {}};
            return {ERROR_ASSEMBLY, {}};
        }
    }

    // from ibench
    if ((globalHandle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        return {ERROR_FILE, {}};
    }
    // get handles to function in the assembly file
    std::unordered_map<std::string, double (*)()> initFunctionMap;
    std::unordered_map<std::string, double (*)(int)> benchFunctionMap;
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

    dbg(__func__, "starting benchmarks");
    struct timeval start, end;
    std::unordered_map<std::string, std::list<double>> benchtimes;
    for (auto benchFunctionEntry : benchFunctionMap) {
        auto benchFunction = benchFunctionEntry.second;
        auto initFunction = initFunctionMap[Assembly.getInitNameFor(benchFunctionEntry.first)];
        for (unsigned i = 0; i < Runs; i++) {
            auto &list = benchtimes[benchFunctionEntry.first];
            // list.insert(list.end(),
            // (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec) + 50000);
            if (initFunction) {
                (*initFunction)();
                // dbg(__func__, "calling init function ",
                // Assembly.getInitNameFor(benchFunctionEntry.first));
            }
            gettimeofday(&start, NULL);
            (*benchFunction)(N);
            gettimeofday(&end, NULL);
            // dbg(__func__, "inserting time ",
            //     (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec),
            //     " for function ", benchFunctionEntry.first);
            list.insert(list.end(),
                        (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
        }
    }

    dlclose(globalHandle);
    return {SUCCESS, benchtimes};
}

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
static std::pair<ErrorCode, double>
measureThroughput(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    double n = 1000000; // loop count
    AssemblyFile assembly;
    ErrorCode EC;
    std::unordered_map<std::string, std::list<double>> benchResults;
    std::string InterlInst = "";
    std::set<MCRegister> usedRegs;
    const MCInstrDesc &desc = Generator->MCII->get(Opcode);

    // special case 1: check for flags dependency and insert interleave instruction
    if (Generator->Arch == Triple::ArchType::x86_64 &&
        desc.hasImplicitUseOfPhysReg(MCRegister::from(X86::EFLAGS)) &&
        desc.hasImplicitUseOfPhysReg(MCRegister::from(X86::EFLAGS))) {
        InterlInst = "	test	rax, rax";
        usedRegs.insert(MCRegister::from(X86::RAX));
        // outs() << Generator->MCII->getName(Opcode).data() << " 1\n";
    }
    // special case 2: check for instructions like add eax, imm
    // those only have one register they write and read to -> per default we would measure latency
    // because of the dependency
    else if (Generator->Arch == Triple::ArchType::x86_64 && desc.getNumOperands() == 1 &&
             desc.implicit_defs().size() > 1) {
        // this breaks the dependency
        InterlInst = "	mov	rax, 42";
        usedRegs.insert(MCRegister::from(X86::RAX));
        // outs() << Generator->MCII->getName(Opcode).data() << " 2\n";
    }

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1, InterlInst, usedRegs);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, benchResults) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    // take minimum of runs (naming convention of funcitons in genTPBenchmark)
    double time1 = *std::min_element(benchResults["tp"].begin(), benchResults["tp"].end());
    double time2 =
        *std::min_element(benchResults["tpUnroll2"].begin(), benchResults["tpUnroll2"].end());
    double time4 =
        *std::min_element(benchResults["tpUnroll4"].begin(), benchResults["tpUnroll4"].end());
    // std::printf("time1: %.3f \n", time1);
    // std::printf("time2: %.3f \n", time2);

    // predict if loop instructions interfere with the execution
    // see README for explanation TODO
    // this is done for two unroll steps to detect if anomalys occurr
    double loopInstr2 = numInst1 * (time2 - 2 * time1) / (time1 - time2); // calculate unroll 1->2
    double loopInstr4 = numInst1 * (time4 - 2 * time2) / (time2 - time4); // calculate unroll 2->4
    if (loopInstr2 < -1 || loopInstr4 < -1) {
        // throughput decreases significantly when unrolling, this is very
        // unususal
        std::printf("   anomaly detected during measurement:\n");
        std::printf("   %.3f instructions interfering with measurement 1->2\n", loopInstr2);
        std::printf("   %.3f instructions interfering with measurement 2->4\n", loopInstr4);
    }
    loopInstr2 = std::max(loopInstr2, 0.0);
    loopInstr4 = std::max(loopInstr4, 0.0);
    double corrected1_2 = time1 / (1e6 * (numInst1 + loopInstr2) / Frequency * (n / 1e9));
    double corrected2_4 = time2 / (1e6 * (numInst1 * 2 + loopInstr4) / Frequency * (n / 1e9));
    if (!InterlInst.empty()) {
        // we did interleave test, this changes the TP
        // TODO this is flawed, need to detect if interleaved instruction runs on same ports or not
        // we can implement this once we have Latency values

        if (InterlInst == "	test	rax, rax") {
            outs() << "correcting " << corrected2_4 << " with TEST64rr"
                   << throughputDatabase[Generator->getOpcode("TEST64rr")] << "\n";
            corrected1_2 -= throughputDatabase[Generator->getOpcode("TEST64rr")];
            corrected2_4 -= throughputDatabase[Generator->getOpcode("TEST64rr")];
        } else {
            outs() << "correcting " << corrected2_4 << " with MOV64ri32 "
                   << throughputDatabase[Generator->getOpcode("MOV64ri32")] << "\n";
            corrected1_2 -= throughputDatabase[Generator->getOpcode("MOV64ri32")];
            corrected2_4 -= throughputDatabase[Generator->getOpcode("MOV64ri32")];
        }
    }
    if (std::abs(corrected1_2 - corrected2_4) > 0.05) {
        double uncorrected1 = time1 / (1e6 * numInst1 / Frequency * (n / 1e9));
        double uncorrected2 = time2 / (1e6 * numInst1 * 2 / Frequency * (n / 1e9));
        std::printf("   anomaly detected during measurement:\n");
        std::printf("   unr1: %.1f, unr2: %.1f, unr4: %.1f\n", time1, time2, time4);
        std::printf("   %.3f uncorrected1 tp\n", uncorrected1);
        std::printf("   %.3f uncorrected2 tp\n", uncorrected2);
        std::printf("   %.3f corrected1_2 tp\n", corrected1_2);
        std::printf("   %.3f corrected2_4 tp\n", corrected2_4);
    }
    // assume calculating the tp using unroll 2 -> 4 yields the best results
    return {SUCCESS, corrected2_4};
}

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
static std::pair<ErrorCode, double> measureLatency(unsigned Opcode, BenchmarkGenerator *Generator,
                                                   double Frequency) {
    const MCInstrDesc &desc = Generator->MCII->get(Opcode);
    if (Generator->isValid(desc) != SUCCESS) return {Generator->isValid(desc), {}};

    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    // unsigned numInst2 = 24;
    double n = 1000000; // loop count
    ErrorCode EC;
    AssemblyFile assembly;
    int helperOpcode;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly, helperOpcode) =
        Generator->genLatBenchmark(Opcode, &numInst1, &helperInstructions);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, benchResults) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    // if (helperOpcode != -1)
    //     std::cout << Generator->MCII->getName(Opcode).data() << " using helper instruction "
    //               << Generator->MCII->getName(helperOpcode).data() << "\n"
    //               << std::flush;

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
                    Generator->MCII->getName(Opcode).data());
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
            auto [helperOpcode, helperReadRegs, helperWriteRegs] = helperInst;
            if (helperOpcode == Opcode) {
                alreadyInHelpers = true;
                break;
            }
        }
        if (!alreadyInHelpers) {
            auto reads = Generator->getPossibleReadRegs(Opcode);
            auto writes = Generator->getPossibleWriteRegs(Opcode);
            helperInstructions.insert(helperInstructions.end(), {Opcode, reads, writes});
        }
    }

    return {SUCCESS, corrected};
}

static std::pair<ErrorCode, double> calculateCycles(double Runtime, double UnrolledRuntime,
                                                    unsigned NumInst, unsigned LoopCount,
                                                    double Frequency) {
    // correct the result using one measurement with NumInst and one with 2*NumInst. This removes
    // overhead of e.g. the loop instructions themselves see README for explanation TODO
    double overheadPerInstruction = NumInst * (UnrolledRuntime - 2 * Runtime) /
                                    (Runtime - UnrolledRuntime); // calculate unroll 1->2
    if (overheadPerInstruction < -1) {
        // throughput decreases significantly when unrolling, this is unlikely to be a good
        // measurement
        return {ERROR_GENERIC, -1};
    }
    double uncorrected = Runtime / (1e6 * NumInst / Frequency * (LoopCount / 1e9));
    double corrected =
        Runtime / (1e6 * (NumInst + overheadPerInstruction) / Frequency * (LoopCount / 1e9));
    dbg(__func__, "uncorrected: ", uncorrected, " overheadPerInstruction: ", overheadPerInstruction,
        " corrected: ", corrected);
    return {SUCCESS, corrected};
}

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI
static std::pair<ErrorCode, double> measureLatency4(std::list<LatMeasurement4> Measurements,
                                                    BenchmarkGenerator *Generator,
                                                    double Frequency) {

    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    // unsigned numInst2 = 24;
    double n = 1000000; // loop count
    ErrorCode EC;
    AssemblyFile assembly;
    std::unordered_map<std::string, std::list<double>> benchResults;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genLatBenchmark4(Measurements, &numInst1);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, benchResults) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    // take minimum of runs. "latency" and "latencyUnrolled" is naming convention defined in
    // runBenchmark()
    double time1 =
        *std::min_element(benchResults["latency"].begin(), benchResults["latency"].end());
    double time2 = *std::min_element(benchResults["latencyUnrolled"].begin(),
                                     benchResults["latencyUnrolled"].end());
    double cycles;
    std::tie(EC, cycles) = calculateCycles(time1, time2, numInst1, n, Frequency);
    if (EC != SUCCESS) {
        // throughput decreases significantly when unrolling, this should not be possible
        std::string chainString = "";
        for (auto m : Measurements) {
            chainString += Generator->MCII->getName(m.opcode).data();
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

// calls one of the measure functions in a subprocess to recover from segfaults during the
// benchmarking process Type = "t" for throughput or "l" for latency
static std::pair<ErrorCode, double> measureInSubprocess(unsigned Opcode,
                                                        BenchmarkGenerator *Generator,
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
        ErrorCode EC;
        double res;
        if (Type == "t")
            std::tie(EC, res) = measureThroughput(Opcode, Generator, Frequency);
        else
            std::tie(EC, res) = measureLatency(Opcode, Generator, Frequency);

        *sharedResult = res;
        *sharedEC = EC;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) return {ERROR_GENERIC, -1};

        ErrorCode EC = *sharedEC;
        double res = *sharedResult;
        munmap(sharedResult, sizeof(int));
        munmap(sharedEC, sizeof(ErrorCode));
        return {EC, res};
    }
}

// calls one of the measure functions in a subprocess to recover from segfaults during the
// benchmarking process Type = "t" for throughput or "l" for latency
static std::pair<ErrorCode, double> measureSafely(unsigned Opcode, BenchmarkGenerator *Generator,
                                                  double Frequency, std::string Type) {

    if (sigsetjmp(jumpBuffer, 1) == 0) {
        ErrorCode EC;
        double res;
        if (Type == "t")
            std::tie(EC, res) = measureThroughput(Opcode, Generator, Frequency);
        else
            std::tie(EC, res) = measureLatency(Opcode, Generator, Frequency);
        return {EC, res};
    } else {
        if (lastSignal == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (lastSignal == SIGILL) return {ILLEGAL_INSTRUCTION, -1};
        if (lastSignal == SIGFPE) return {ERROR_SIGFPE, -1};

        return {ERROR_UNREACHABLE, -1}; // should be unreachable
    }
}

static std::pair<ErrorCode, double> measureSafely(std::list<LatMeasurement4> Measurements,
                                                  BenchmarkGenerator *Generator, double Frequency,
                                                  std::string Type) {
    std::string dbgString = "";
    for (auto m : Measurements)
        dbgString += Generator->latMeasurement4ToString(m) + " >>> ";
    dbg(__func__, "measuring ", dbgString.data());
    if (sigsetjmp(jumpBuffer, 1) == 0) {
        ErrorCode EC;
        double res;
        if (Type == "t")
            // std::tie(EC, res) = measureThroughput(Opcode, Generator, Frequency);
            outs() << "you didnt implement that idiot";
        else
            std::tie(EC, res) = measureLatency4(Measurements, Generator, Frequency);
        return {EC, res};
    } else {
        if (lastSignal == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (lastSignal == SIGILL) return {ILLEGAL_INSTRUCTION, -1};
        if (lastSignal == SIGFPE) return {ERROR_SIGFPE, -1};

        return {ERROR_UNREACHABLE, -1}; // should be unreachable
    }
}

static void displayProgress(int progress, int total) {
    int barWidth = 50;
    float ratio = progress / (float)total;
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
    std::cerr << "] " << int(ratio * 100.0) << "% " << progress << "/" << total << std::flush;
}

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
static int buildTPDatabase(double Frequency, unsigned MaxOpcode = 0) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();
    if (MaxOpcode == 0) MaxOpcode = generator.MCII->getNumOpcodes();

    // measure TEST64rr and MOV64ri32 beforehand, because their tps are needed for interleaving
    // with other instructions
    outs() << generator.getOpcode("TEST64rr") << "\n";
    outs() << generator.getOpcode("MOV64ri32") << "\n";
    if (generator.Arch == Triple::ArchType::x86_64) {
        auto [EC, tp] =
            measureInSubprocess(generator.getOpcode("TEST64rr"), &generator, Frequency, "t");
        if (EC == SUCCESS) throughputDatabase[generator.getOpcode("TEST64rr")] = tp;
        auto [EC2, tp2] =
            measureInSubprocess(generator.getOpcode("MOV64ri32"), &generator, Frequency, "t");
        if (EC2 == SUCCESS) throughputDatabase[generator.getOpcode("MOV64ri32")] = tp2;
    }

    for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
        displayProgress(opcode, MaxOpcode);
        std::string name = generator.MCII->getName(opcode).data();
        if (skipInstructions.find(name) != skipInstructions.end()) {
            outs() << name << ": " << "skipped for reason\t " << "skippedManually" << "\n";
            continue;
        }

        auto [EC, tp] = measureInSubprocess(opcode, &generator, Frequency, "t");
        name.resize(27, ' ');
        throughputDatabase[opcode] = tp;

        if (EC != SUCCESS) {
            outs() << name << ": " << "skipped for reason\t " << ecToString(EC) << "\n";
            outs().flush();
            continue;
        }

        std::printf("%s: %.3f (clock cycles)\n", name.data(), tp);
        fflush(stdout);
    }
    return 0;
}

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
static int buildLatDatabase(double Frequency, unsigned MaxOpcode = 0) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();

    std::unordered_set<unsigned> skipOpcodes;
    for (auto name : skipInstructions) {
        skipOpcodes.insert(generator.getOpcode(name));
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

            auto [EC, lat] = measureSafely(opcode, &generator, Frequency, "l");
            errorCodeDatabase[opcode] = EC;
            latencyDatabase[opcode] = lat;
            if (EC == SUCCESS) gotNewMeasurement = true;
        }
    }
    // print results
    for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
        std::string name = generator.MCII->getName(opcode).data();
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
static bool equalWithTolerance(double a, double b) { return std::abs(a - b) <= 0.1 * a; }
static bool smallerEqWithTolerance(double a, double b) { return a < b || equalWithTolerance(a, b); }
static bool isSus(double a) { return !equalWithTolerance(std::round(a), a); }

static bool hasConnectionTo(std::vector<std::pair<unsigned, unsigned>> Values, unsigned First,
                            unsigned Second) {
    for (auto v : Values)
        if (v.first == First && v.second == Second) return true;

    return false;
}

static std::string pairVectorToString(std::vector<std::pair<unsigned, unsigned>> Values) {
    std::string result = "[";
    for (auto v : Values) {
        result += "(" + std::to_string(v.first) + ", " + std::to_string(v.second) + "), ";
    }
    result += "]";
    return result;
}

static std::string pairVectorToString2(std::vector<std::pair<unsigned, unsigned>> Values) {
    std::string result = "[";
    for (auto v : Values) {
        result += std::to_string(v.first) + "-" + std::to_string(v.second) + ", ";
    }
    result += "]";
    return result;
}

static std::vector<std::pair<unsigned, unsigned>>
findFullyConnected(std::vector<std::pair<unsigned, unsigned>> Edges, unsigned Number) {
    if (Number == 1 && !Edges.empty()) return {Edges[0]};
    if (Edges.size() != 0) dbg(__func__, "Edges: ", pairVectorToString2(Edges));

    for (auto chosenEdge : Edges) {
        dbg(__func__, "chosen: ", chosenEdge.first, " ", chosenEdge.second);
        std::vector<std::pair<unsigned, unsigned>> edgesReduced;
        // for full connection the edges in the next recursion need to be between nodes which both
        // have a connection to the nodes of the chosen edge
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

static bool isVariant(unsigned a, unsigned b, BenchmarkGenerator &generator) {
    // check if a and b are the same instruction with different operands
    std::string nameA = generator.MCII->getName(a).data();
    std::string nameB = generator.MCII->getName(b).data();
    if (nameA == nameB) return true;
    // llvm names for the same instruction normally match until the first occurrence of a number
    // e.g. ADD8ri_EVEX ADD8ri_ND ADD8ri_NF ADD8ri_NF_ND
    auto getPrefixWithFirstNumber = [](const std::string &name) -> std::string {
        size_t i = 0;
        // Find the start of the first number
        while (i < name.size() && !isdigit(name[i]))
            ++i;

        // include the whole number
        size_t j = i;
        while (j < name.size() && isdigit(name[j]))
            ++j;

        return name.substr(0, j);
    };

    std::string namePrefixA = getPrefixWithFirstNumber(nameA);
    std::string namePrefixB = getPrefixWithFirstNumber(nameB);
    if (namePrefixA == namePrefixB) dbg(__func__, "found variant: ", nameA, " ", nameB);
    return namePrefixA == namePrefixB;
}

static void findHelperInstructions(std::vector<LatMeasurement4> measurements,
                                   BenchmarkGenerator &generator, double Frequency) {
    dbg(__func__, "number of measurements: ", measurements.size());
    // classify measurements by operand combination
    std::map<LatMeasurementType, std::vector<LatMeasurement4>> classifiedMeasurements;
    for (auto m : measurements)
        classifiedMeasurements[m.type].emplace_back(m);

    for (auto classified : classifiedMeasurements)
        dbg(__func__, "class: ", generator.latMeasurementTypeToString(classified.first));

    // to measure latencys of e.g. REG -> FLAGS we need some instruction (called helper
    // instruction) with known latency FLAGS -> REG so we can interleave the two. We determine one
    // such reference for each non trivial (non REG-> REG) latency operand to use in the main
    // benchmarking phase.
    // holds a helper instruction for every LatencyOperand combination.
    std::map<LatMeasurementType, LatMeasurement4> helperInstructions;
    std::set<LatMeasurementType> noHelperPossible;
    for (auto [mType, typeA] : classifiedMeasurements) {
        if (helperInstructions.find(mType) != helperInstructions.end()) continue;
        if (noHelperPossible.find(mType) != noHelperPossible.end()) continue;
        if (mType.defOp == mType.useOp) {
            // trivial case
            for (auto m : typeA) {
                auto [EC, lat] =
                    measureSafely({m}, &generator, Frequency, "l"); // TODO check if this is correct
                if (EC != 0 || lat < 2 || isSus(lat)) continue;
                // use first successful measurement as helper
                m.value = lat;
                helperInstructions.insert({mType, m});
                dbg(__func__, "found helper trivial: ", generator.latMeasurement4ToString(m));
                break;
            }
            continue;
        }
        // if (!(std::holds_alternative<MCRegister>(mType.useOp) &&
        //       std::get<MCRegister>(mType.useOp) == X86::EFLAGS)) {
        //     continue;
        // }

        dbg(__func__, "searching helper for type: ", generator.latMeasurementTypeToString(mType));
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
        // for (unsigned i = 0; i < typeA.size(); i++) {
        //     dbg(__func__, i, " ", generator.MCII->getName(typeA[i].opcode).data());
        // }
        // for (unsigned i = 0; i < typeB.size(); i++) {
        //     dbg(__func__, i, " ", generator.MCII->getName(typeB[i].opcode).data());
        // }
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
                    if (isVariant(typeA[indexA].opcode, typeA[i].opcode, generator)) {
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
                        measureSafely({typeA[indexA], typeB[b]}, &generator, Frequency, "l");
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
                    if (isVariant(typeB[indexB].opcode, typeB[i].opcode, generator)) {
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
                        measureSafely({typeA[a], typeB[indexB]}, &generator, Frequency, "l");
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
            dbg(__func__, "no helper for ", generator.latMeasurementTypeToString(mType));
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
        dbg(__func__, "found a helper for ",
            generator.latMeasurementTypeToString(measurementA.type));
        dbg(__func__, "found a helper for opposite type ",
            generator.latMeasurementTypeToString(measurementB.type));
    }
    for (auto [mType, m] : classifiedMeasurements) {
        // LatMeasurement4 *inst = helperInstructions.find(mType);
        if (helperInstructions.find(mType) == helperInstructions.end()) {
            dbg(__func__, "no helper for ", generator.latMeasurementTypeToString(mType),
                "searching for replacement");
            // until now for e.g. xmm1 -> class(GR64) only instructions of exactly this type were
            // considered, however if no suitable instructions were found we can use instructions
            // with class(VR128X) -> class(GR64) as well.
            std::set<LatOperandType> replacementDefClassIDs;
            if (std::holds_alternative<MCRegister>(mType.defOp)) {
                auto reg = std::get<MCRegister>(mType.defOp);
                replacementDefClassIDs.insert(reg);
                // TODO test if base class check is enough or if we need this check
                for (unsigned i = 0; i < generator.MRI->getNumRegClasses(); i++) {
                    if (!generator.regInRegClass(reg, i)) continue;
                    replacementDefClassIDs.insert(regClass(i));
                }
            } else {
                // this is already a class, we can use it directly
                replacementDefClassIDs.insert(std::get<unsigned>(mType.defOp));
            }
            std::set<LatOperandType> replacementUseClassIDs;
            if (std::holds_alternative<MCRegister>(mType.useOp)) {
                auto reg = std::get<MCRegister>(mType.useOp);
                replacementUseClassIDs.insert(reg);
                for (unsigned i = 0; i < generator.MRI->getNumRegClasses(); i++) {
                    if (!generator.regInRegClass(reg, i)) continue;
                    replacementUseClassIDs.insert(regClass(i));
                }
            } else {
                // this is already a class, we can use it directly
                replacementUseClassIDs.insert(std::get<unsigned>(mType.useOp));
            }
            // check if we have helpers for any combination of the replacement classes
            bool found = false;
            for (auto defOpType : replacementDefClassIDs) {
                for (auto useOpType : replacementUseClassIDs) {
                    LatMeasurementType replacementType = LatMeasurementType(defOpType, useOpType);
                    if (helperInstructions.find(replacementType) != helperInstructions.end()) {
                        // we have a helper for this type, use it for the current type
                        LatMeasurement4 m = helperInstructions.at(replacementType);
                        helperInstructions.insert({mType, m});
                        dbg(__func__, "using", generator.latMeasurement4ToString(m),
                            "as replacement helper for ",
                            generator.latMeasurementTypeToString(mType));
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
            if (!found) {
                dbg(__func__, "still no helper");
            }
        } else {
            LatMeasurement4 m = helperInstructions.at(mType);
            dbg(__func__, "helper for ", generator.latMeasurementTypeToString(mType), " ",
                generator.MCII->getName(m.opcode).data(), " ", m.value);
        }
    }
    for (auto [mType, m] : helperInstructions) {
        std::string name = generator.MCII->getName(m.opcode).data();
        name.resize(27, ' ');
        dbg(__func__, "helper for ",generator.latMeasurementTypeToString(mType), ": ", generator.latMeasurement4ToString(m), " ", m.value);
    }
}

// measure the first MaxOpcode instructions or all if MaxOpcode is zero or not supplied
static int buildLatDatabase4(double Frequency, unsigned MaxOpcode = 0) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();

    std::unordered_set<unsigned> skipOpcodes;
    for (auto name : skipInstructions) {
        skipOpcodes.insert(generator.getOpcode(name));
    }

    // auto measurements = generator.genLatMeasurements();
    std::vector<LatMeasurement4> measurements =
        generator.genLatMeasurements4(MaxOpcode, skipOpcodes);
    findHelperInstructions(measurements, generator, Frequency);
    // for (auto [mType, m] : helperInstructions) {
    //     dbg(__func__, "opcode", m.opcode);
    //     std::string name = generator.MCII->getName(m.opcode).data();
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

    //         if (skipOpcodes.find(opcode) != skipOpcodes.end()) {
    //             errorCodeDatabase[opcode] = SKIP_MANUALLY;
    //             continue;
    //         }

    //         auto [EC, lat] = measureSafely(opcode, &generator, Frequency, "l");
    //         errorCodeDatabase[opcode] = EC;
    //         latencyDatabase[opcode] = lat;
    //         if (EC == SUCCESS) gotNewMeasurement = true;
    //     }
    // }
    // // print results
    // for (unsigned opcode = 0; opcode < MaxOpcode; opcode++) {
    //     std::string name = generator.MCII->getName(opcode).data();
    //     name.resize(27, ' ');

    //     if (errorCodeDatabase[opcode] == SUCCESS) {
    //         std::printf("%s: %.3f (clock cycles) Lat\n", name.data(),
    //         latencyDatabase[opcode]); fflush(stdout);
    //     } else {
    //         outs() << name << ": " << "skipped for reason\t "
    //                << ecToString(errorCodeDatabase[opcode]) << "\n";
    //         outs().flush();
    //     }
    // }
    return 0;
}

// studies

static void runOverlapStudy(unsigned Opcode1, unsigned Opcode2, unsigned InstLimit,
                            BenchmarkGenerator *Generator, double Frequency) {

    std::list<std::pair<unsigned, unsigned>> ratios;
    ratios.push_back({1, 1});
    for (unsigned i = 2; i < InstLimit; i++) {
        ratios.push_front({i, 1});
        ratios.push_back({1, i});
    }
    for (auto ratio : ratios) {
        ErrorCode EC;
        AssemblyFile assembly;
        unsigned numInst1 = ratio.first;
        unsigned numInst2 = ratio.second;
        std::string ratio_string = std::to_string(ratio.first) + ":" + std::to_string(ratio.second);

        // std::tie(EC, assembly) =
        //     Generator->genOverlapBenchmark(Opcode1, Opcode2, numInst1, numInst2, 20);
        std::tie(EC, assembly) = Generator->genOverlapBenchmark(Opcode1, Opcode2, numInst1,
                                                                numInst2, 20, "\tmov	rax, 42");
        if (EC != SUCCESS) {
            outs() << ratio_string << " cannot generate ratio\n";
            continue;
        }
        std::unordered_map<std::string, std::list<double>> times1;
        unsigned n = 1e6;
        std::tie(EC, times1) = runBenchmark(assembly, n, 3);

        if (EC != SUCCESS)
            outs() << ratio_string << " cannot run ratio\n";
        else {
            double time1 = *std::min_element(times1["latency"].begin(), times1["latency"].end());
            double tp1 = time1 / (1e6 * numInst1 * 20 / Frequency * (n / 1e9));
            double tp2 = time1 / (1e6 * numInst2 * 20 / Frequency * (n / 1e9));
            double tp_comb = time1 / (1e6 * (numInst1 + numInst2) * 20 / Frequency * (n / 1e9));
            outs() << ratio_string << " time " << time1 << " tp_1 " << tp1 << " tp_2 " << tp2
                   << " tp_comb " << tp_comb << "\n";
        }
    }
}

int main(int argc, char **argv) {
    struct option long_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"instruction", required_argument, nullptr, 'i'},
        {"frequency", required_argument, nullptr, 'f'},
        {"cpu", required_argument, nullptr, 'c'},
        {"march", required_argument, nullptr, 'm'},
        {"ninst", required_argument, nullptr, 'n'},
        {nullptr, 0, nullptr, 0} // End marker
    };
    std::vector<std::string> instrNames;
    double frequency = 3.75;
    int opt;
    std::string cpu = "";
    std::string march = "";
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

    argc -= 1; // Shift arguments
    argv += 1;
    while ((opt = getopt_long(argc, argv, "hi:f:m:n:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            std::cout << "Usage:" << argv[0]
                      << "[--help] [--instruction INST] [--frequency FREQ(GHz)] [--ninst nMax]\n";
            return 0;
        case 'i':
            instrNames.emplace_back(optarg);
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
        case 'n':
            maxOpcode = atoi(optarg);
            break;
        default:
            return 1;
        }
    }
    dbgToFile = false;
    struct timeval start, end;
    gettimeofday(&start, NULL);

    BenchmarkGenerator generator = BenchmarkGenerator();
    ErrorCode EC = generator.setUp(march, cpu);
    if (EC == ERROR_TARGET_DETECT) {
        errs() << "could not detect target, please specify using --cpu or --arch\n"; // TODO
                                                                                     // implement
        exit(EXIT_FAILURE);
    }

    // setup signal handler to recover from various signals
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Default behavior

    sigaction(SIGSEGV, &sa, nullptr); // Handle segmentation faults
    sigaction(SIGILL, &sa, nullptr);  // Handle illegal instructions
    sigaction(SIGFPE, &sa, nullptr);  // Handle floating-point exceptions

    if (maxOpcode == 0) maxOpcode = generator.MCII->getNumOpcodes();
    latencyDatabase.resize(maxOpcode, -1.0);
    errorCodeDatabase.resize(maxOpcode, ERROR_NO_HELPER);
    switch (mode) {
    case INTERLEAVE: {
        unsigned opcode1 = generator.getOpcode(instrNames[0]);
        unsigned opcode2 = generator.getOpcode(instrNames[1]);
        runOverlapStudy(opcode1, opcode2, 16, &generator, frequency);
        break;
    }
    case TP: {
        if (instrNames.empty()) {
            buildTPDatabase(frequency, maxOpcode);
            break;
        }
        if (instrNames.size() > 2) {
            outs() << "only one instruction supported\n";
            break;
        }
        dbgToFile = true;
        unsigned opcode = generator.getOpcode(instrNames[0]);
        if (generator.Arch == Triple::ArchType::x86_64) {
            auto [EC, tp] =
                measureInSubprocess(generator.getOpcode("TEST64rr"), &generator, frequency, "t");
            if (EC == SUCCESS) throughputDatabase[generator.getOpcode("TEST64rr")] = tp;
            auto [EC2, tp2] =
                measureInSubprocess(generator.getOpcode("MOV64ri32"), &generator, frequency, "t");
            if (EC2 == SUCCESS) throughputDatabase[generator.getOpcode("MOV64ri32")] = tp2;
        }
        auto [EC, tp] = measureInSubprocess(opcode, &generator, frequency, "t");
        if (EC != SUCCESS) {
            outs() << "failed for reason: " << ecToString(EC) << "\n";
            outs().flush();
        } else {
            std::printf("%.3f (clock cycles)\n", tp);
            fflush(stdout);
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
            // std::vector<std::pair<unsigned, unsigned>> values = {
            //     {1, 4}, {1, 5}, {1, 6}, {2, 4}, {2, 5}, {2, 6}, {3, 4}, {3, 5}, {3, 6},
            // };
            // auto v = findFullyConnected(values, 3);
            // dbg(__func__, "found ", v.size(), " fully connected values: ",
            // pairVectorToString(v));
            buildLatDatabase4(frequency, maxOpcode);
            break;
        }
        dbgToFile = true;
        debug = true;
        for (auto instrName : instrNames) {
            unsigned opcode = generator.getOpcode(instrName.data());

            auto [EC, lat] = measureSafely(opcode, &generator, frequency, "l");
            if (EC != SUCCESS) {
                outs() << "failed for reason: " << ecToString(EC) << "\n";
                outs().flush();
            } else {
                std::printf("%.3f (clock cycles)\n", lat);
                fflush(stdout);
            }
            latencyDatabase[generator.getOpcode(instrName)] = lat;
        }
        break;
    }
    }
    gettimeofday(&end, NULL);
    auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    printf("total runtime: %f (s)\n", totalRuntime);
    std::cerr << " done\n";

    return 0;
}

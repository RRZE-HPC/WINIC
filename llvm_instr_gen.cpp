// #include "MCTargetDesc/X86MCTargetDesc.h"
#include "MCTargetDesc/X86BaseInfo.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "benchmarkGenerator.cpp"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
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
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>
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
        dbg("dlclose called\n");
    }
    lastSignal = Signum;
    siglongjmp(jumpBuffer, 1); // Jump back to safe point
}

static std::pair<ErrorCode, std::list<double>> runBenchmark(std::string Assembly, int N,
                                                            unsigned Runs) {
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return {ERROR_FILE, {-1}};
    }
    asmFile << Assembly;
    asmFile.close();
    if (dbgToFile) {
        std::string DebugPath =
            "/home/hpc/ihpc/ihpc149h/bachelor/llvm-project/build/own_tools/llvm-bench/debug.s";
        std::ofstream debugFile(DebugPath);
        if (!debugFile) {
            std::cerr << "Failed to create debug file" << std::endl;
            return {ERROR_FILE, {-1}};
        }
        debugFile << Assembly;
        debugFile.close();
    }
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path
    // + " -o " + o_path;
    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    // "gcc -x assembler-with-cpp -shared -mfp16-format=ieee " + sPath + " -o " + oPath + " 2>
    // gcc_out";
    std::string compiler = CLANG_PATH;
    std::string command = compiler + " -x assembler-with-cpp -shared " + sPath + " -o " + oPath;
    if (dbgToFile)
        command += " 2> assembler_out.log";
    else
        command += " 2> /dev/null";
    if (system(command.data()) != 0) return {ERROR_ASSEMBLY, {-1}};

    // from ibench
    // void *handle;
    double (*latency)(int);
    int *ninst;
    if ((globalHandle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        fflush(stdout);
        return {ERROR_FILE, {-1}};
    }
    if ((latency = (double (*)(int))dlsym(globalHandle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        fflush(stdout);
        return {ERROR_GENERIC, {-1}};
    }
    if ((ninst = (int *)dlsym(globalHandle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        fflush(stdout);
        return {ERROR_GENERIC, {-1}};
    }

    struct timeval start, end;

    // struct sigaction sa;
    // sa.sa_handler = signalHandler;
    // sigemptyset(&sa.sa_mask);
    // sa.sa_flags = 0;
    // sigaction(SIGILL, &sa, nullptr);

    std::list<double> benchtimes;

    // if (sigsetjmp(jumpBuffer, 1) == 0) {
    for (unsigned i = 0; i < Runs; i++) {
        gettimeofday(&start, NULL);
        (*latency)(N);
        gettimeofday(&end, NULL);
        benchtimes.insert(benchtimes.end(),
                          (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
    }
    // } else {
    //     dlclose(handle);
    //     return {ILLEGAL_INSTRUCTION, {-1}};
    // }

    dlclose(globalHandle);
    return {SUCCESS, benchtimes};
}

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI so dont call from main process
static std::pair<ErrorCode, double>
measureThroughput(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    unsigned numInst2 = 12;
    unsigned numInst4 = 12;
    double n = 1000000; // loop count
    std::string assembly;
    ErrorCode EC;
    std::list<double> times1;
    std::list<double> times2;
    std::list<double> times4;
    std::string InterlInst = "";
    std::set<MCRegister> usedRegs;
    const MCInstrDesc &desc = Generator->MCII->get(Opcode);

    // special case 1: check for flags dependency and insert interleave instruction
    if (Generator->Arch == Triple::ArchType::x86_64 &&
        desc.hasImplicitUseOfPhysReg(MCRegister::from(X86::EFLAGS)) &&
        desc.hasImplicitUseOfPhysReg(MCRegister::from(X86::EFLAGS))) {
        InterlInst = "	test	rax, rax";
        usedRegs.insert(MCRegister::from(X86::RAX));
        outs() << Generator->MCII->getName(Opcode).data() << " 1\n";
    }
    // special case 2: check for instructions like add eax, imm
    // those only have one register they write and read to -> per default we would measure latency
    // because of the dependency
    else if (Generator->Arch == Triple::ArchType::x86_64 && desc.getNumOperands() == 1 &&
             desc.implicit_defs().size() > 1) {
        // this breaks the dependency
        InterlInst = "	mov	rax, 42";
        usedRegs.insert(MCRegister::from(X86::RAX));
        outs() << Generator->MCII->getName(Opcode).data() << " 2\n";
    }
    // else if (Opcode != 5016 && Opcode != 2567) {
    //     outs() << "sus return error\n";
    //     outs().flush();
    //     //
    //     return {ERROR_GENERIC, 0.25};
    // }

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1, InterlInst, usedRegs);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times1) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst2, 2, InterlInst, usedRegs);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times2) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst4, 4, InterlInst, usedRegs);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times4) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    // take minimum of runs
    double time1 = *std::min_element(times1.begin(), times1.end());
    double time2 = *std::min_element(times2.begin(), times2.end());
    double time4 = *std::min_element(times4.begin(), times4.end());
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
    double corrected2_4 = time2 / (1e6 * (numInst2 + loopInstr4) / Frequency * (n / 1e9));
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
        double uncorrected2 = time2 / (1e6 * numInst2 / Frequency * (n / 1e9));
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
// this may segfault e.g. on privileged instructions like CLGI so dont call from main process
static std::pair<ErrorCode, double> measureLatency(unsigned Opcode, BenchmarkGenerator *Generator,
                                                   double Frequency) {
    const MCInstrDesc &desc = Generator->MCII->get(Opcode);
    if (Generator->isValid(desc) != SUCCESS) return {Generator->isValid(desc), {}};

    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation or CPUID
    unsigned numInst1 = 12;
    unsigned numInst2 = 24;
    double n = 1000000; // loop count
    ErrorCode EC;
    std::string assembly;
    int helperOpcode;
    std::list<double> times1;
    std::list<double> times2;
    // std::set<MCRegister> usedRegs;

    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly, helperOpcode) =
        Generator->genLatBenchmark(Opcode, &numInst1, &helperInstructions);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times1) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly, helperOpcode) =
        Generator->genLatBenchmark(Opcode, &numInst2, &helperInstructions);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times2) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    // take minimum of runs
    double time1 = *std::min_element(times1.begin(), times1.end());
    double time2 = *std::min_element(times2.begin(), times2.end());
    // std::printf("time1: %.3f \n", time1);
    // std::printf("time2: %.3f \n", time2);

    // predict if loop instructions interfere with the execution
    // see README for explanation TODO
    // this is done for two unroll steps to detect if anomalys occurr
    double loopInstr2 = numInst1 * (time2 - 2 * time1) / (time1 - time2); // calculate unroll 1->2
    if (loopInstr2 < -1) {
        // throughput decreases significantly when unrolling, this is very
        // unususal
        std::printf("   anomaly detected during measurement:\n");
        std::printf("   %.3f instructions interfering with measurement 1->2\n", loopInstr2);
    }
    loopInstr2 = std::max(loopInstr2, 0.0);
    double corrected1_2 = time1 / (1e6 * (numInst1 + loopInstr2) / Frequency * (n / 1e9));
    // if a helper instruction was used subtract its latency
    if (helperOpcode != -1) corrected1_2 -= latencyDatabase[helperOpcode];

    return {SUCCESS, corrected1_2};
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

// measure the first maxNum instructions or all if maxNum is zero or not supplied
static int buildTPDatabase(double Frequency, unsigned MaxNum = 0) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();
    if (MaxNum == 0) MaxNum = generator.MCII->getNumOpcodes();

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

    for (unsigned opcode = 0; opcode < MaxNum; opcode++) {
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

// measure the first maxNum instructions or all if maxNum is zero or not supplied
static int buildLatDatabase(double Frequency, unsigned MaxNum = 0) {
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

    if (MaxNum == 0) MaxNum = generator.MCII->getNumOpcodes();
    latencyDatabase.resize(MaxNum, -1.0);
    errorCodeDatabase.resize(MaxNum, ERROR_NO_HELPER);

    bool gotNewMeasurement = true;
    // rerun multiple times if more helper instructions are available now
    while (gotNewMeasurement) {
        gotNewMeasurement = false;
        for (unsigned opcode = 0; opcode < MaxNum; opcode++) {
            displayProgress(opcode, MaxNum);
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
    for (unsigned opcode = 0; opcode < MaxNum; opcode++) {
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

// studies
static void runBenchmarkStudy(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency,
                              int N) {
    ErrorCode EC;
    std::string assembly;
    unsigned numInst1 = 12;
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1);
    for (unsigned i = 0; i < 10; i++) {
        auto [EC, Times] = runBenchmark(assembly, N, 10);
        for (auto t : Times) {
            auto tp = t / (1e6 * numInst1 / Frequency * (N / 1e9));
            std::printf("%.3f, ", tp);
        }
        std::printf("\n");
    }
}

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
        std::string assembly;
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
        std::list<double> times1;
        unsigned n = 1e6;
        std::tie(EC, times1) = runBenchmark(assembly, n, 3);

        if (EC != SUCCESS)
            outs() << ratio_string << " cannot run ratio\n";
        else {
            double time1 = *std::min_element(times1.begin(), times1.end());
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
    struct option overlap_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"instruction1", required_argument, nullptr, 'i'},
        {"instruction2", required_argument, nullptr, 's'},
        {"frequency", required_argument, nullptr, 'v'},
        {"cpu", required_argument, nullptr, 'c'},
        {"march", required_argument, nullptr, 'm'},
        {"ninst", required_argument, nullptr, 'n'},
        {nullptr, 0, nullptr, 0} // End marker
    };
    StringRef instrName = "";
    StringRef instrName2 = "";
    double frequency = 3.75;
    int opt;
    std::string cpu = "";
    std::string march = "";
    unsigned maxNum = 0;
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

    if (mode == TP || mode == LAT || mode == DEV) {
        argc -= 1; // Shift arguments
        argv += 1;
        while ((opt = getopt_long(argc, argv, "hi:f:m:n:", long_options, nullptr)) != -1) {
            switch (opt) {
            case 'h':
                std::cout
                    << "Usage:" << argv[0]
                    << "[--help] [--instruction INST] [--frequency FREQ(GHz)] [--ninst nMax]\n";
                return 0;
            case 'i':
                instrName = optarg;
                break;
            case 's':
                instrName2 = optarg;
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
                maxNum = atoi(optarg);
                break;
            default:
                return 1;
            }
        }
    } else if (mode == INTERLEAVE) {
        argc -= 1; // Shift arguments
        argv += 1;
        while ((opt = getopt_long(argc, argv, "hi:f:m:n:", overlap_options, nullptr)) != -1) {
            switch (opt) {
            case 'h':
                std::cout << "Usage:" << argv[0]
                          << "[--help] [--instruction1 INST] [--instruction2 INST] [--frequency "
                             "FREQ(GHz)] [--ninst nMax]\n";
                return 0;
            case 'i':
                instrName = optarg;
                break;
            case 's':
                instrName2 = optarg;
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
                maxNum = atoi(optarg);
                break;
            default:
                return 1;
            }
        }

    } else {
        std::cerr << "Unknown subprogram: " << mode << "\n";
        return 1;
    }
    // srun --cpu-freq=2400000-2400000:performance ./llvm_instr_gen LAT -f 2.4 -n 1000 >
    // genoaLat.log
    BenchmarkGenerator generator = BenchmarkGenerator();
    ErrorCode EC = generator.setUp(march, cpu);
    if (EC == ERROR_TARGET_DETECT) {
        errs() << "could not detect target, please specify using --cpu or --arch\n"; // TODO
                                                                                     // implement
        exit(EXIT_FAILURE);
    }
    dbgToFile = false;
    struct timeval start, end;
    gettimeofday(&start, NULL);

    // setup signal handler to recover from various signals
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Default behavior

    sigaction(SIGSEGV, &sa, nullptr); // Handle segmentation faults
    sigaction(SIGILL, &sa, nullptr);  // Handle illegal instructions
    sigaction(SIGFPE, &sa, nullptr);  // Handle floating-point exceptions

    // generator.temp(opcode);
    // runBenchmarkStudy(opcode, &generator, frequency, 1000000);
    // studyUnrollBehavior(opcode, &generator, frequency);
    switch (mode) {
    case INTERLEAVE: {
        unsigned opcode1 = generator.getOpcode(instrName.data());
        unsigned opcode2 = generator.getOpcode(instrName2.data());
        runOverlapStudy(opcode1, opcode2, 16, &generator, frequency);
        break;
    }
    case TP: {
        if (instrName == "") {
            buildTPDatabase(frequency, maxNum);
            break;
        }
        dbgToFile = true;
        unsigned opcode = generator.getOpcode(instrName.data());
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
        if (instrName == "") {
            buildLatDatabase(frequency, maxNum);
            break;
        }
        dbgToFile = true;
        unsigned opcode = generator.getOpcode(instrName.data());

        auto [EC, tp] = measureSafely(opcode, &generator, frequency, "l");
        if (EC != SUCCESS) {
            outs() << "failed for reason: " << ecToString(EC) << "\n";
            outs().flush();
        } else {
            std::printf("%.3f (clock cycles)\n", tp);
            fflush(stdout);
        }
        break;
    }
    case DEV: {
        dbgToFile = true;
        if (instrName == "") outs() << "need instruction\n";
        auto [EC, lat] = measureSafely(generator.getOpcode("ADC16ri8"), &generator, frequency, "l");
        if (EC != SUCCESS) {
            outs() << "lat failed for reason: " << ecToString(EC) << "\n";
            outs().flush();
        }
        latencyDatabase[generator.getOpcode("ADC16ri8")] = lat;
        auto [EC2, lat2] =
            measureSafely(generator.getOpcode("CMP16ri"), &generator, frequency, "l");
        if (EC2 != SUCCESS) {
            outs() << "lat2 failed for reason: " << ecToString(EC2) << "\n";
            outs().flush();
        }
        latencyDatabase[generator.getOpcode("CMP16ri")] = lat2;
        std::printf("ADC16ri8: %.3f (clock cycles)\n", lat);
        std::printf("CMP16ri: %.3f (clock cycles)\n", lat2);
        // generator.isLatencyHelperInstruction(generator.getOpcode(instrName.data()),
        // X86::RAX);
    }
    }
    gettimeofday(&end, NULL);
    auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    printf("total runtime: %f (s)\n", totalRuntime);
    std::cerr << " done\n";

    return 0;
}

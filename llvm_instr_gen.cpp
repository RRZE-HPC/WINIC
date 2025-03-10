// #include "MCTargetDesc/X86MCTargetDesc.h"
#include "MCTargetDesc/X86BaseInfo.h"
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
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include <algorithm>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <math.h>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

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



using namespace llvm;
static bool dbgToFile = true;

// Global jump buffer for recovery from illegal instruction
static sigjmp_buf jumpBuffer;

// Signal handler for illegal instruction
static void sigillHandler(int Signum) {
    // std::cerr << "Caught SIGILL (Illegal Instruction), recovering...\n";
    siglongjmp(jumpBuffer, 1); // Jump back to safe point
}

static std::pair<ErrorCode, std::list<double>> runBenchmark(std::string Assembly, int N,
                                                            unsigned Runs) {
    std::string sPath = "/dev/shm/temp.s";
    std::string oPath = "/dev/shm/temp.so";
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return {ERROR_GENERIC, {-1}};
    }
    asmFile << Assembly;
    asmFile.close();
    if (dbgToFile) {
        std::string DebugPath =
            "/home/hpc/ihpc/ihpc149h/bachelor/llvm-project/build/own_tools/llvm-bench/debug.s";
        std::ofstream debugFile(DebugPath);
        if (!debugFile) {
            std::cerr << "Failed to create debug file" << std::endl;
            return {ERROR_GENERIC, {-1}};
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
    void *handle;
    double (*latency)(int);
    int *ninst;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        fflush(stdout);
        return {ERROR_GENERIC, {-1}};
    }
    if ((latency = (double (*)(int))dlsym(handle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        fflush(stdout);
        return {ERROR_GENERIC, {-1}};
    }
    if ((ninst = (int *)dlsym(handle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        fflush(stdout);
        return {ERROR_GENERIC, {-1}};
    }

    struct timeval start, end;

    struct sigaction sa;
    sa.sa_handler = sigillHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGILL, &sa, nullptr);
    std::list<double> benchtimes;

    if (sigsetjmp(jumpBuffer, 1) == 0) {
        for (unsigned i = 0; i < Runs; i++) {
            gettimeofday(&start, NULL);
            (*latency)(N);
            gettimeofday(&end, NULL);
            benchtimes.insert(benchtimes.end(), (end.tv_sec - start.tv_sec) * 1000000 +
                                                    (end.tv_usec - start.tv_usec));
        }
    } else {
        dlclose(handle);
        return {ILLEGAL_INSTRUCTION, {-1}};
    }

    dlclose(handle);
    return {SUCCESS, benchtimes};
}

// runs two benchmarks to correct eventual interference with loop instructions
// this may segfault e.g. on privileged instructions like CLGI so dont call from main process
static std::pair<ErrorCode, double>
measureThroughput(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    // make the generator generate up to 12 instructions, this ensures reasonable runtimes on slow
    // instructions like random value generation
    unsigned numInst1 = 12;
    unsigned numInst2 = 12;
    unsigned numInst4 = 12;

    double n = 1000000; // loop count
    std::string assembly;
    ErrorCode EC;
    std::list<double> times1;
    std::list<double> times2;
    std::list<double> times4;
    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times1) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst2, 2);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times2) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst4, 4);
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
    int anomalyLevel = 0;
    if (loopInstr2 < -1 || loopInstr4 < -1)
        anomalyLevel = 5; // throughput decreases significantly when unrolling, this is very
                          // unususal
    loopInstr2 = std::max(loopInstr2, 0.0);
    loopInstr4 = std::max(loopInstr4, 0.0);

    double uncorrected1 = time1 / (1e6 * numInst1 / Frequency * (n / 1e9));
    double uncorrected2 = time2 / (1e6 * numInst2 / Frequency * (n / 1e9));
    double corrected1_2 = time1 / (1e6 * (numInst1 + loopInstr2) / Frequency * (n / 1e9));
    double corrected2_4 = time2 / (1e6 * (numInst2 + loopInstr4) / Frequency * (n / 1e9));
    if (std::abs(corrected1_2 - corrected2_4) > 0.05) anomalyLevel = 2;

    if (anomalyLevel != 0) {
        std::printf("   anomalys detected during measurement:\n");
        std::printf("   unr1: %.1f, unr2: %.1f, unr4: %.1f\n", time1, time2, time4);
        std::printf("   %.3f instructions interfering with measurement 1->2\n", loopInstr2);
        std::printf("   %.3f instructions interfering with measurement 2->4\n", loopInstr4);
        std::printf("   %.3f uncorrected1 tp\n", uncorrected1);
        std::printf("   %.3f uncorrected2 tp\n", uncorrected2);
        std::printf("   %.3f corrected1_2 tp\n", corrected1_2);
        std::printf("   %.3f corrected2_4 tp\n", corrected2_4);
    }
    // assume calculating the tp using unroll 2 -> 4 yields the best results
    return {SUCCESS, corrected2_4};
}

// calls measureThroughput in a subprocess to recover from segfaults during the benchmarking process
static std::pair<ErrorCode, double>
measureThroughputSubprocess(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    // allocate memory for communicating result
    double *sharedTP = static_cast<double *>(
        mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ErrorCode *sharedEC = static_cast<ErrorCode *>(
        mmap(NULL, sizeof(ErrorCode), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));

    if (sharedTP == MAP_FAILED || sharedEC == MAP_FAILED) {
        perror("mmap");
        return {ERROR_MMAP, -1};
    }

    pid_t pid = fork();
    if (pid == -1) {
        return {ERROR_FORK, -1};
    }

    if (pid == 0) { // Child process
        auto [EC, tp] = measureThroughput(Opcode, Generator, Frequency);
        *sharedTP = tp;
        *sharedEC = EC;
        exit(EXIT_SUCCESS);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) return {ERROR_SIGSEGV, -1};
        if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) return {ERROR_GENERIC, -1};

        ErrorCode EC = *sharedEC;
        double tp = *sharedTP;
        munmap(sharedTP, sizeof(int));
        munmap(sharedEC, sizeof(ErrorCode));
        return {EC, tp};
    }
}

// measure the first maxNum instructions or all if maxNum is zero or not supplied
static int buildDatabase(double Frequency, unsigned MaxNum = 0) {
    // skip instructions which take long and are irrelevant
    std::set<std::string> skipInstructions = {
        "SYSCALL",   "CPUID",     "MWAITXrrr", "RDRAND16r", "RDRAND32r", "RDRAND64r", "RDSEED16r",
        "RDSEED32r", "RDSEED64r", "RDTSC",     "SLDT16r",   "SLDT32r",   "SLDT64r",   "SMSW16r",
        "SMSW32r",   "SMSW64r",   "STR16r",    "STR32r",    "STR64r",    "VERRr",     "VERWr"};
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();
    if (MaxNum == 0) MaxNum = generator.MCII->getNumOpcodes();
    for (unsigned opcode = 0; opcode < MaxNum; opcode++) {
        // get instruction information
        std::string name = generator.MCII->getName(opcode).data();
        if (skipInstructions.find(name) != skipInstructions.end()) {
            outs() << name << ": " << "skipped for reason\t " << "skippedManually" << "\n";
            continue;
        }
        auto [EC, tp] = measureThroughputSubprocess(opcode, &generator, Frequency);
        name.resize(27, ' ');

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

int main(int argc, char **argv) {
    struct option long_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"instruction", required_argument, nullptr, 'i'},
        {"frequency", required_argument, nullptr, 'v'},
        {"cpu", required_argument, nullptr, 'c'},
        {"march", required_argument, nullptr, 'm'},
        {"ninst", required_argument, nullptr, 'n'},
        {nullptr, 0, nullptr, 0} // End marker
    };
    StringRef instrName = "";
    // unsigned numInst = 6;
    // unsigned unrollCount = 1;
    double frequency = 3.75;
    int opt;
    std::string cpu = "";
    std::string march = "";
    unsigned maxNum = 0;
    while ((opt = getopt_long(argc, argv, "hi:f:m:n:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            std::cout << "Usage:" << argv[0]
                      << "[--help] [--instruction INST] [--frequency FREQ(GHz)] [--ninst nMax]\n";
            return 0;
        case 'i':
            instrName = optarg;
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

    BenchmarkGenerator generator = BenchmarkGenerator();
    ErrorCode EC = generator.setUp(march, cpu);
    if (EC == ERROR_TARGET_DETECT) {
        errs() << "could not detect target, please specify using --cpu or --arch\n"; // TODO
                                                                                     // implement
        exit(EXIT_FAILURE);
    }

    if (instrName == "") {
        dbgToFile = false;
        struct timeval start, end;
        gettimeofday(&start, NULL);
        buildDatabase(frequency, maxNum);
        gettimeofday(&end, NULL);
        auto totalRuntime = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        printf("total runtime: %f (s)\n", totalRuntime);
    } else {
        // debug = true;
        unsigned opcode = generator.getOpcode(instrName.data());

        // generator.temp(opcode);
        // runBenchmarkStudy(opcode, &generator, frequency, 1000000);
        // studyUnrollBehavior(opcode, &generator, frequency);
        auto [EC, tp] = measureThroughputSubprocess(opcode, &generator, frequency);
        if (EC != SUCCESS) {
            outs() << "failed for reason: " << ecToString(EC) << "\n";
            outs().flush();
        } else {
            std::printf("%.3f (clock cycles)\n", tp);
            fflush(stdout);
        }
    }

    return 0;
}

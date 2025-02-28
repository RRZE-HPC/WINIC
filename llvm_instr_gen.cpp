// #include "MCTargetDesc/X86MCTargetDesc.h"
#include "benchmarkGenerator.cpp"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
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
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <math.h>
#include <numeric>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

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

/*
TODO
    some instructions e.g. adc on zen4 get a TP penalty when unrolling the loop without
    breaking the dependency on the flags. try to avoid
    replace generic errors
    move to clang for assembling to avoid gcc dependency
    test other arches
    add templates for other arches
    init registers (e.g. avoid avx-sse transition penalty)
    instructions with weird values
        ADD_FST0r
        XOR8rr_NOREX
        ADC16ri8

    -MCInstrPrinter segfaults when instruction is wrong (or is Prefix)
    -check filtering memory instructions
    -implement loop instruction interference detection
    -compile and run from inside program
    -save callee saved registers

State
    Conditional moves measure garbage CMOVNE_F
    ND and EVEX encoded variants cause ERROR_ASSEMBLY (this is ok, normal variants get measured)


Questions:
    compilation time

*/

// helpful
// TRI->getRegAsmName(MCRegister)

using namespace llvm;
// using namespace X86;

static bool debug = false;
static bool dbgToFile = true;
template <typename... Args> static void dbg(Args &&...args) {
    if (debug) {
        (outs() << ... << args) << "\n";
        outs().flush();
    }
}

// Global jump buffer for recovery
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
        if (!asmFile) {
            std::cerr << "Failed to create file in /dev/shm/" << std::endl;
            return {ERROR_GENERIC, {-1}};
        }
        debugFile << Assembly;
        debugFile.close();
    }
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path
    // + " -o " + o_path;
    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    std::string command =
        "gcc -x assembler-with-cpp -shared " + sPath + " -o " + oPath + " 2> gcc_out";
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
    double benchtime;

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

    double n = 1000000; // loop count
    std::string assembly;
    ErrorCode EC;
    std::list<double> times1;
    std::list<double> times2;
    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst1, 1);
    if (EC != SUCCESS) return {EC, -1};
    std::tie(EC, times1) = runBenchmark(assembly, n, 3);
    if (EC != SUCCESS) return {EC, -1};

    std::tie(EC, assembly) = Generator->genTPBenchmark(Opcode, &numInst2, 2);
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
    double loopInstr = numInst1 * (time2 - 2 * time1) / (time1 - time2);

    int nLoopInstr = std::round(loopInstr);

    if (nLoopInstr != 0) {
        std::printf("debug: %.3f instructions interfering with measurement\n", loopInstr);
        fflush(stdout);
    }
    // double uncorrected = time1 / (1e6 * numInst1 / Frequency * (n / 1e9));
    double intCorrected = time1 / (1e6 * (numInst1 + nLoopInstr) / Frequency * (n / 1e9));
    // double floatCorrected = time1 / (1e6 * (numInst1 + loopInstr) / Frequency * (n / 1e9));

    // std::printf("%.3f uncorrected tp\n", uncorrected);
    // std::printf("%.3f intCorrected tp\n", intCorrected);
    // std::printf("%.3f floatCorrected tp\n", floatCorrected);
    return {SUCCESS, intCorrected};
}

static double simpleMeasurement(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency,
                                unsigned *NumInst, unsigned UnrollCount) {
    unsigned n = 1e6;
    // numInst gets updated to the actual number of instructions generated by genTPBenchmark
    auto [EC, assembly] = Generator->genTPBenchmark(Opcode, NumInst, UnrollCount);
    auto [EC2, times] = runBenchmark(assembly, n, 1);
    double time = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double tp = time / (1e6 * *NumInst / Frequency * (n / 1e9));
    outs() << time << "\n";
    outs().flush();
    std::printf("%.3f clock cycles\n", tp);
    fflush(stdout);
    return 0;
}

// calls measureThroughput in a subprocess to recover from segfaults during the benchmarking process
static std::pair<ErrorCode, double>
measureThroughputSubprocess(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
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
    BenchmarkGenerator generator = BenchmarkGenerator();
    generator.setUp();
    if (MaxNum == 0) MaxNum = generator.MCII->getNumOpcodes();
    for (unsigned opcode = 0; opcode < MaxNum; opcode++) {
        auto [EC, tp] = measureThroughputSubprocess(opcode, &generator, Frequency);
        std::string name = generator.MCII->getName(opcode).data();
        name.resize(19, ' ');
        if (EC != SUCCESS) {
            // if (EC != MAY_LOAD && EC != MAY_STORE && EC != MEMORY_OPERAND)
            outs() << name << ": " << "skipped for reason\t " << ecToString(EC) << "\n";
            outs().flush();
            continue;
        }
        // outs() << generator.MCII->getName(opcode) << ": " << tp << " (clock cycles)\n";
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

static void studyUnrollBehavior(unsigned Opcode, BenchmarkGenerator *Generator, double Frequency) {
    unsigned N = 1000000;

    for (unsigned i = 1; i < 61; i++) {
        unsigned numInst1 = i;
        auto [EC, assembly] = Generator->genTPBenchmark(Opcode, &numInst1, 1, true);
        auto [EC1, Times] = runBenchmark(assembly, N, 10);
        double time1 = *std::min_element(Times.begin(), Times.end());
        auto tp = time1 / (1e6 * numInst1 / Frequency * (N / 1e9));
        std::printf("(%i, %.3f), ", i, tp);

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
        {"number", required_argument, nullptr, 'n'},
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
                      << "[--help] [--instruction INST] [--frequency FREQ(GHz)] [--number nMax]\n";
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
        errs()
            << "could not detect target, please specify using --cpu or --arch\n"; // TODO implement
        exit(EXIT_FAILURE);
    }

    if (instrName == "")
        buildDatabase(frequency, maxNum);
    else {
        debug = true;
        unsigned opcode = generator.getOpcode(instrName.data());

        // generator.temp(opcode);
        // runBenchmarkStudy(opcode, &generator, frequency, 1000000);
        studyUnrollBehavior(opcode, &generator, frequency);
        // auto [EC, tp] = measureThroughputSubprocess(opcode, &generator, frequency);
        // if (EC != SUCCESS) {
        //     outs() << "failed for reason: " << ecToString(EC) << "\n";
        //     outs().flush();
        // } else {
        //     std::printf("%.3f (clock cycles)\n", tp);
        //     fflush(stdout);
        // }
    }

    return 0;
}

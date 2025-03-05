#include <algorithm>
#include <csetjmp>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <list>
#include <math.h>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static sigjmp_buf jumpBuffer;

// Signal handler for illegal instruction
static void sigillHandler(int Signum) {
    // std::cerr << "Caught SIGILL (Illegal Instruction), recovering...\n";
    siglongjmp(jumpBuffer, 1); // Jump back to safe point
}

static std::list<double> runBenchmark(int N, unsigned Runs, unsigned *NumInst, double Frequency) {
    std::string sPath = "./debug.s";
    std::string oPath = "/dev/shm/temp.so";
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path
    // + " -o " + o_path;
    // gcc -x assembler-with-cpp -shared /dev/shm/temp.s -o /dev/shm/temp.so &> gcc_out"
    // "gcc -x assembler-with-cpp -shared " + sPath + " -o " + oPath + " 2> gcc_out";
    std::string command =
        "/home/hpc/ihpc/ihpc149h/bachelor/llvm-project/build_all/bin/clang -x assembler-with-cpp -shared " + sPath + " -o " + oPath + " 2> compiler_out";
    if (system(command.data()) != 0) return {-1};

    // from ibench
    void *handle;
    double (*latency)(int);
    int *ninst;
    if ((handle = dlopen(oPath.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .so file\n");
        fflush(stdout);
        return {-1};
    }
    if ((latency = (double (*)(int))dlsym(handle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        fflush(stdout);
        return {-1};
    }
    if ((ninst = (int *)dlsym(handle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        fflush(stdout);
        return {-1};
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
            // actual call to benchmarked function
            (*latency)(N);
            gettimeofday(&end, NULL);
            benchtimes.insert(benchtimes.end(), (end.tv_sec - start.tv_sec) * 1000000 +
                                                    (end.tv_usec - start.tv_usec));
        }
    } else {
        dlclose(handle);
        return {-1};
    }
    *NumInst = *ninst;

    dlclose(handle);
    return benchtimes;
}

int main(int argc, char **argv) {
    unsigned numInst = 12;
    if (argc != 2) {
        std::cerr << "usage: quick <frequency>\n";
        exit(EXIT_FAILURE);
    }
    double Frequency = atof(argv[1]);
    unsigned N = 10000000;
    auto times = runBenchmark(N, 3, &numInst, Frequency);
    for (auto time : times) {
        std::cout << time << " ";
    }
    double time1 = *std::min_element(times.begin(), times.end());
    std::cout << " min: " << time1 << " numInst: " << numInst << "\n";

    double tp = time1 / (1e6 * numInst / Frequency * (N / 1e9));
    std::printf("%.3f (clock cycles)\n", tp);

    return 0;
}
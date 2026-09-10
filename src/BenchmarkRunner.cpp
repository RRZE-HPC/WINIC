#include "BenchmarkRunner.h"

#include "AssemblyFile.h"
#include "CustomDebug.h"
#include "ErrorCode.h"
#include "Globals.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#ifndef WINIC_CLANG_PATH
#define WINIC_CLANG_PATH "usr/bin/clang"
#endif

namespace winic {

ErrorCode BenchmarkRunner::assembleBenchmark(AssemblyFile Assembly) {
    std::ofstream asmFile(sPath);
    if (!asmFile) {
        out(std::cerr, "Failed to create file in ", sPath);
        return E_FILE;
    }
    asmFile << Assembly.generateAssembly();
    asmFile.close();
    if (outputASM) {
        std::string asmPath =
            std::filesystem::current_path().string() + "/asm/" + Assembly.getName() + ".s";
        std::ofstream debugFile(asmPath);
        if (!debugFile) {
            std::cerr << "Failed to create debug file at " << asmPath.data() << std::endl;
        } else {
            debugFile << Assembly.generateAssembly();
            debugFile.close();
        }
    }

    return assembleBenchmark(sPath);
}

ErrorCode BenchmarkRunner::assembleBenchmark(std::string SPath) {
    // assemble benchmark
    pid_t pid = fork();
    if (pid == 0) { // Child
        int fd;
        if (outputASM) {
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
        std::string cpu = getEnv().Machine->getTargetCPU().data();
        std::string archOption;
        if (getEnv().isRISCV() && cpu.find("generic") != std::string::npos) {
            // generic riscv64 will fail to assemble benchmarks, use very
            // permissive -march flag as workaround
            cpu = "rv64gcv_zba_zbb_zbc_zbs_zicbom_zicbop_zicboz_zfh_zfhmin_zvl128b_zvl256b";
            archOption = str("-march=", cpu);
        } else {
            archOption = str("-mcpu=", cpu);
        }

        execl(WINIC_CLANG_PATH, "clang", archOption.data(), "-nostdlib", "-x", "assembler-with-cpp",
              "-shared", SPath.data(), "-o", soPath.data(), nullptr);
        _exit(127);       // execl failed
    } else if (pid > 0) { // Parent
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            if (WEXITSTATUS(status) == 127) return E_EXEC;
            return E_ASSEMBLY;
        }
    }
    return SUCCESS;
}

std::pair<ErrorCode, std::unordered_map<std::string, std::vector<double>>>
BenchmarkRunner::runBenchmark(AssemblyFile Assembly, unsigned LoopIterations, unsigned Runs) {
    if (Runs == 0) return {E_NO_RUNS, {}};
    dbg(__func__, "N: ", LoopIterations, " Runs: ", Runs);

    // from ibench
    void *handle = nullptr;
    if ((handle = dlopen(soPath.data(), RTLD_LAZY)) == NULL) {
        const char *err = dlerror();
        out(std::cerr, "\ndlopen: failed to open .so file: ", (err ? err : "unknown error"));

        return {E_FILE, {}};
    }
    // get handles to function in the assembly file
    std::unordered_map<std::string, double (*)(int)> benchFunctionMap;
    std::unordered_map<std::string, double (*)()> initFunctionMap;
    for (std::string functionName : Assembly.getInitFunctionNames()) {
        auto functionPtr = (double (*)())dlsym(handle, functionName.data());
        if (functionPtr == NULL) {
            const char *error = dlerror();
            out(std::cerr, "dlsym: couldn't find function ", functionName, " ",
                error != nullptr ? error : "");
            dlclose(handle);
            return {E_GENERIC, {}};
        }
        initFunctionMap[functionName] = functionPtr;
    }
    for (std::string functionName : Assembly.getBenchFunctionNames()) {
        auto functionPtr = (double (*)(int))dlsym(handle, functionName.data());
        if (functionPtr == NULL) {
            out(std::cerr, "dlsym: couldn't find function ", functionName.data());
            dlclose(handle);
            return {E_GENERIC, {}};
        }
        benchFunctionMap[functionName] = functionPtr;
    }
    // may have results from prior runs
    struct timeval start, end;
    std::unordered_map<std::string, std::vector<double>> benchtimes;

    for (auto [benchFunctionName, benchFunctionPointer] : benchFunctionMap) {
        auto benchFunction = benchFunctionPointer;
        auto initFunction = initFunctionMap[Assembly.getInitNameFor(benchFunctionName)];
        auto &list = benchtimes[benchFunctionName];
        unsigned numInst = Assembly.getNumInstFor(benchFunctionName);
        double runtimeLimit =
            maxCyclesPerInstruction * (numInst * LoopIterations) / (clockFrequency * 1e3);

        dbg(__func__, "running ", Assembly.getName(), " function: ", benchFunctionName);
        for (unsigned i = 0; i < Runs; i++) {
            (*benchFunction)(3);

            gettimeofday(&start, NULL);
            (*benchFunction)(LoopIterations);
            gettimeofday(&end, NULL);

            double benchtime =
                (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
            list.insert(list.end(), benchtime);
            if (benchtime > runtimeLimit) {
                dlclose(handle);
                return {S_RUNTIME_LIMIT, benchtimes};
            }
        }
    }

    dlclose(handle);
    for (auto [name, times] : benchtimes) {
        dbg(__func__, "benchtimes for ", name, ": ", times);
    }

    return {SUCCESS, benchtimes};
}

} // namespace winic
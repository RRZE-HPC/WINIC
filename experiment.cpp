
// #include "MCTargetDesc/X86MCTargetDesc.h"
#include "templates.cpp"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/RegisterBankInfo.h"
// #include "llvm/IR/Instructions.h"
// #include "llvm/IR/Module.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCInst.h"
// #include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <memory>
#include <string>
// using namespace llvm;

#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>
// llvm-mc --mcpu=ivybridge --preserve-comments --filetype=obj temp.s

int execute(std::string assembly) {

    // buffer for assembled file
    ssize_t bufferSize = 0;
    unsigned char asm_buffer[2048];

    int in_pipe[2], out_pipe[2];
    pipe(in_pipe);
    pipe(out_pipe);

    // assemble file using llvm-mc
    pid_t pid = fork();
    if (pid == 0) { // Child process
        close(in_pipe[1]);
        close(out_pipe[0]);

        // Redirect stdin to read from in_pipe
        dup2(in_pipe[0], STDIN_FILENO);
        close(in_pipe[0]);

        // Redirect stdout to write to out_pipe
        dup2(out_pipe[1], STDOUT_FILENO);
        close(out_pipe[1]);

        // execvp("llvm-mc", "--mcpu=ivybridge", "--preserve-comments", "--filetype=obj", NULL);
        char *args[] = {"llvm-mc", "--mcpu=ivybridge", "--filetype=obj", NULL};
        // char *args[] = {"echo", "echo", NULL};
        execvp(args[0], args);
        perror("execlp failed");
        return 1;
    } else if (pid > 0) { // Parent process
        close(in_pipe[0]);
        close(out_pipe[1]);

        // Send assembly to child for assembling
        const char *data = assembly.data();
        write(in_pipe[1], data, strlen(data));
        close(in_pipe[1]);

        // Read output from child's stdout
        // bufferSize = read(STDIN_FILENO, asm_buffer, sizeof(asm_buffer));
        std::cout << "starting read\n";
        ssize_t bytesRead;
        while ((bytesRead = read(out_pipe[0], asm_buffer, sizeof(asm_buffer))) > 0) {
            // After reading, you can treat the buffer as a string or process the data
            if (bufferSize > sizeof(asm_buffer)) {
                std::cerr << "Error: Buffer is too small to hold all data. " << bufferSize
                          << " bytes read, but the buffer size is " << sizeof(asm_buffer)
                          << " bytes." << std::endl;
                exit(EXIT_FAILURE); // Fail the program if buffer is too small
            }
            // asm_buffer[bufferSize] = '\0';
            bufferSize += bytesRead;
        }
        std::cout << "end read\n";
        std::cout << bufferSize << "\n";

        close(out_pipe[0]); // Close read end
        wait(NULL);         // Wait for child to finish
    } else {
        std::cerr << "fork failed!\n";
        return 1;
    }

    // benchmark assembled file
    //  unsigned char code[] = {
    //      0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42
    //      0xC3                           // ret
    //  };

    // Allocate memory (RWX: Read, Write, Execute)
    std::cout << "mma" << "\n";
    void *exec_mem = mmap(NULL, bufferSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    // Copy machine code into allocated memory
    std::cout << "memcpy" << "\n";
    memcpy(exec_mem, asm_buffer, bufferSize);

    struct timeval start, end;
    double result;
    // Cast memory to function pointer
    std::cout << "cast" << "\n";
    double (*latency)(int) = (double (*)(int))exec_mem;

    int N = 1e6; // number of Loops

    // Execute function
    std::cout << "time" << "\n";
    gettimeofday(&start, NULL);
    std::cout << "exec" << "\n";
    result = (*latency)(N);
    std::cout << "exec done" << "\n";
    gettimeofday(&end, NULL);
    std::cout << "Result: " << result << "\n";

    // Free memory
    munmap(exec_mem, sizeof(asm_buffer));

    // std::string AsmCode = "mov rax, 1\n"
    //                       "mov rdi, 1\n"
    //                       "syscall\n";
    // std::unique_ptr<MemoryBuffer> Buffer = MemoryBuffer::getMemBuffer(AsmCode);
    // std::string command = "llvm-mc --mcpu ivybridge --preserve-comments --filetype obj";
    // FILE *pipe = popen("ls -l", "w"); // Open a pipe to the command
    // if (!pipe) {
    //     llvm::errs() << "popen failed!\n";
    //     return 1;
    // }

    // char buffer[128];
    // while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    //     std::cout << buffer;
    // }
    // std::cout << "hi";

    // pclose(pipe);
    return 1;
}

double benchmark(std::string assembly, int N) {
    std::string s_path = "/dev/shm/temp.s";
    std::string o_path = "/dev/shm/temp.so";
    std::ofstream asmFile(s_path);
    if (!asmFile) {
        std::cerr << "Failed to create file in /dev/shm/" << std::endl;
        return 1;
    }
    asmFile << assembly;
    asmFile.close();
    // std::string command = "llvm-mc --mcpu=ivybridge --filetype=obj " + s_path + " -o " + o_path;
    std::string command = "gcc -x assembler-with-cpp -shared " + s_path + " -o " + o_path;
    system(command.data());

    //from ibench
    void *handle;
    double (*latency)(int);
    int *ninst;
    if ((handle = dlopen(o_path.data(), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: failed to open .o file\n");
        exit(EXIT_FAILURE);
    }
    if ((latency = (double (*)(int))dlsym(handle, "latency")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find function latency\n");
        return (EXIT_FAILURE);
    }
    if ((ninst = (int *)dlsym(handle, "ninst")) == NULL) {
        fprintf(stderr, "dlsym: couldn't find symbol ninst\n");
        return (EXIT_FAILURE);
    }

    struct timeval start, end;
    double result;
    double benchtime;

    gettimeofday(&start, NULL);
    result = (*latency)(N);
    gettimeofday(&end, NULL);
    benchtime = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
    // printf("%.3f (benchtime)\n",  benchtime);
    return benchtime;
}

int main(int argc, char **argv) {
    std::string assembly = R"(#define NINST 12

.intel_syntax noprefix
.globl ninst
.data
ninst:
.long NINST
.text
.globl latency
.type latency, @function
.align 32
latency:
        push      rbp
        mov       rbp, rsp
        xor       r8d, r8d
        test      edi, edi

        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        jle       done
loop:
        inc       r8d
        add     rax, 42
        add     rcx, 42
        add     rdx, 42
        add     rsi, 42
        add     r9, 42
        add     r10, 42
        add     r11, 42
        add     rbx, 42
        add     r14, 42
        add     r15, 42
        add     r12, 42
        add     r13, 42
        cmp       r8d, edi
        jl        loop
done:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
        mov  rsp, rbp
        pop rbp
        ret
.size latency, .-latency)";
    //     std::string assembly = R"(
    // .intel_syntax noprefix
    // .text
    // .align 32
    // latency:
    //         mov rax, 42
    //         ret
    // )";
    //     std::string assembly = R"(.intel_syntax noprefix
    // .text
    // add     r12, 42
    // ret)";
    benchmark(assembly, 1000000);
    return 0;
}

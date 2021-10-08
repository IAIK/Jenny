#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <assert.h>
#include "../../pk/pk_debug.h"

FILE* ftiming = NULL;
uint64_t* timing_start = NULL;

extern char **environ;

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Provide program to execute, e.g.:\n");
        printf("    %s   /bin/bash -c 'echo Hi'\n\n", argv[0]);
        printf("The resulting execution timing will be stored in the file provided\n");
        printf("via the environment variable OVERALL\n\n");
        printf("The environment variables starting with 'MY_' will be renamed to 'LD_'\n");
        printf("before being passed to the program-to-execute\n");
        printf("For example, 'MY_PRELOAD' will be renamed to 'LD_PRELOAD'\n");
        return -1;
    }

    for (char** envp = environ; *envp != NULL; *envp++) {
        if (strncmp(*envp, "MY_", 3) == 0) {
            strncpy(*envp, "LD_", 3);
        }
    }

    char* file = getenv("OVERALL");
    if (file) {
        printf("Will append timing results to %s", file);
        ftiming = fopen(file, "a");
        if (!ftiming) {
            perror("fopen failed");
            printf("Could not open FILE %s", file);
            exit(-1);
        }
    }
    if (!ftiming) {
        ftiming = stderr;
    }

    // Make timing_start survive fork
    timing_start = mmap(NULL, sizeof(*timing_start), PROT_READ | PROT_WRITE, 
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == timing_start) {
        perror("mmap failed");
        return -1;
    }

    pid_t child = fork();
    if (-1 == child) {
        perror("fork failed");
        exit(-1);
    }
    if (child == 0) {
        // we're in the child
        *timing_start = RDTSC();
        execve(argv[1], &argv[1], environ);
        perror("execve failed");
        exit(-1);
    } else {
        // we're in the parent
        waitpid(child, NULL, 0);
        uint64_t timing_stop = RDTSC();
        assert(*timing_start != 0);
        fprintf(ftiming, "%" PRIu64 "\n", timing_stop - *timing_start);
    }
}

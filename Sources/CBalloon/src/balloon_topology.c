// CPU topology and thread-affinity helpers.
//
// BalloonHash is memory-bound (2^24 random reads into a 512 MB scratchpad),
// so SMT siblings on the same physical core fight for L1/L2 and slow each
// other down. The right default on a 16c/32t machine is 16 threads, each
// pinned to a distinct physical core.

// _GNU_SOURCE is needed for pthread_setaffinity_np / CPU_SET on glibc.
#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "balloon_fast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#include <pthread.h>
#include <dirent.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

// ---------------------------------------------------------------------------
// Physical core enumeration (Linux)
// ---------------------------------------------------------------------------

#if defined(__linux__)

// A physical-core "representative" logical CPU is the one whose ID is the
// smallest in its thread_siblings_list. Picking only representatives gives
// us one logical CPU per physical core, which is what we want for pinning.
static int read_first_int(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static int cmp_ints(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    return (ia > ib) - (ia < ib);
}

static int collect_online_cpus(int *out, int max) {
    DIR *d = opendir("/sys/devices/system/cpu");
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        int cpu = -1;
        if (sscanf(e->d_name, "cpu%d", &cpu) == 1 && cpu >= 0) {
            out[n++] = cpu;
        }
    }
    closedir(d);
    qsort(out, (size_t)n, sizeof(int), cmp_ints);
    return n;
}

#endif

int balloon_physical_core_cpu_ids(int *out, int max) {
#if defined(__linux__)
    if (max <= 0) return 0;
    int cpus[1024];
    int ncpus = collect_online_cpus(cpus, 1024);
    int count = 0;
    for (int k = 0; k < ncpus && count < max; k++) {
        int cpu = cpus[k];
        char path[256];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
                 cpu);
        int first = read_first_int(path);
        if (first == cpu) {
            out[count++] = cpu;
        }
    }
    return count;
#else
    (void)out; (void)max;
    return 0;
#endif
}

int balloon_physical_core_count(void) {
#if defined(__linux__)
    int tmp[1024];
    int n = balloon_physical_core_cpu_ids(tmp, 1024);
    if (n > 0) return n;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    return nproc > 0 ? (int)nproc : 1;
#elif defined(__APPLE__)
    int count = 0;
    size_t sz = sizeof(count);
    if (sysctlbyname("hw.physicalcpu", &count, &sz, NULL, 0) == 0 && count > 0) {
        return count;
    }
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    return nproc > 0 ? (int)nproc : 1;
#else
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    return nproc > 0 ? (int)nproc : 1;
#endif
}

// ---------------------------------------------------------------------------
// Thread pinning
// ---------------------------------------------------------------------------

int balloon_pin_current_thread(int cpu_id) {
#if defined(__linux__)
    if (cpu_id < 0) return -1;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    // pid=0 binds the calling thread (each thread is its own kernel task on Linux).
    return sched_setaffinity(0, sizeof(set), &set);
#else
    (void)cpu_id;
    return 0;
#endif
}

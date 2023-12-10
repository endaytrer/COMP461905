/* DO NOT MODIFY */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "Loader.h"
#include "LoaderInternal.h"

char *sys_path[64] = {
    "test_lib",
    "/lib",
    "/usr/lib",
    "/usr/local/lib",
    "/lib/aarch64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    ""
};

int envlen = 7;

__attribute__((constructor))
static void init() {
    char ld_library_path[1024];
    const char *env = getenv("LD_LIBRARY_PATH");
    if (!env) return;
    strcpy(ld_library_path, env);
    char *ptr = ld_library_path;
    while (true) {
        char *tok = strtok(ptr, ":");
        if (tok == NULL) {
            sys_path[envlen++] = NULL;
            break;
        }
        char *str = malloc(strlen(tok));
        strcpy(str, tok);
        sys_path[envlen++] = str;
        
        ptr = NULL;
    }
}

void *OpenLibrary(const char *libpath, int mode)
{
    LinkMap *new = MapLibrary(libpath);
    
    if (!new) return NULL;

    RelocLibrary(new, mode);

    InitLibrary(new);

    return new;
}
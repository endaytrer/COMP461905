/* DO NOT MODIFY */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "Loader.h"
#include "LoaderInternal.h"

char *sys_path[64] = {
    "/lib",
    "/usr/lib",
    "test_lib",
    ""
};

__attribute__((constructor))
static void init() {
    char ld_library_path[128];
    const char *env = getenv("LD_LIBRARY_PATH");
    if (env == NULL) return;
    strncpy(ld_library_path, env, 128);
    int envlen = 4;
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

    RelocLibrary(new, mode);

    InitLibrary(new);

    return new;
}

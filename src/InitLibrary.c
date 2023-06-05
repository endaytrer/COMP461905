#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    
    void (*initf)();
    if (l->dynInfo[DT_INIT]) {
        initf = (void (*)())l->dynInfo[DT_INIT]->d_un.d_ptr;
        initf();
    }
    if (l->dynInfo[DT_INIT_ARRAYSZ]) {

        size_t initc = l->dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val / sizeof(void (*)());
        void (**initv)();
        initv = (void (**)())l->dynInfo[DT_INIT_ARRAY]->d_un.d_ptr;
        for (size_t i = 0; i < initc; i++) {
            initv[i]();
        }
    }

    /* Your code here */
}

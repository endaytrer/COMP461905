#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    /* Your code here */

    if (l->dynInfo[DT_INIT])
    {
        void (*Init_1st)(void) = (void *)l->dynInfo[DT_INIT]->d_un.d_ptr;
        Elf64_Addr *Init_array = (void *)l->dynInfo[DT_INIT_ARRAY]->d_un.d_ptr;
        uint64_t array_size = (uint64_t)l->dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val;
        array_size = (uint64_t)(array_size / sizeof(Elf64_Addr));

        Init_1st();

        for (uint64_t i = 0; i < array_size; i++)
        {
            void (*Init_2ed)(void) = (void *)*Init_array;
            if ((uint64_t)Init_2ed < (uint64_t)l->addr)
                Init_2ed += l->addr;
            Init_2ed();
            Init_array++;
        }
    }
}

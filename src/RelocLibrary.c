#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
    if (dep->fake)
    {
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if (!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            abort();
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; // not this dependency
}

void RelocLibrary(LinkMap *lib, int mode)
{
    /* Your code here */
    if (lib->dynInfo[DT_JMPREL])
    {
        Elf64_Rela *PLT_reloc_addr = (Elf64_Rela *)lib->dynInfo[DT_JMPREL]->d_un.d_ptr;
        u_int64_t PLT_size = lib->dynInfo[DT_PLTRELSZ]->d_un.d_val;
        Elf64_Sym *Table_sym_addr = (Elf64_Sym *)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
        const char *Table_sym_str_addr = (const char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
        // void *handle = dlopen("libc.so.6", RTLD_LAZY);
        for (u_int64_t i = 0; i < PLT_size / sizeof(Elf64_Rela); ++i)
        {
            int PLT_index = (PLT_reloc_addr[i].r_info) >> 32;
            const char *str_addr = (Table_sym_str_addr + Table_sym_addr[PLT_index].st_name);

            // void *address = dlsym(handle, (const char *)str_addr);
            void *address = symbolLookup(lib, (const char *)str_addr);

            if (lib->searchList != NULL)
            {
                address = symbolLookup(lib->searchList[0], str_addr);
            }

            Elf64_Addr *got_addr = (Elf64_Addr *)(lib->addr + PLT_reloc_addr[i].r_offset);
            *got_addr = (Elf64_Addr)(address + PLT_reloc_addr[i].r_addend);
        }
    }

    if (lib->dynInfo[DT_RELA])
    {
        Elf64_Rela *rela_addr = (Elf64_Rela *)lib->dynInfo[DT_RELA]->d_un.d_ptr;
        u_int64_t rela_size = lib->dynInfo[DT_RELACOUNT_NEW]->d_un.d_val;

        for (u_int64_t i = 0; i < rela_size; ++i)
        {
            Elf64_Addr *got_addr = (Elf64_Addr *)(lib->addr + rela_addr[i].r_offset);
            *got_addr = (Elf64_Addr)(lib->addr + rela_addr[i].r_addend);
        }

        u_int64_t rela_glob_size = lib->dynInfo[DT_RELASZ]->d_un.d_val;
        u_int64_t rela_glob_sz = lib->dynInfo[DT_RELAENT]->d_un.d_val;
        rela_glob_size = rela_glob_size / rela_glob_sz;

        Elf64_Sym *Table_sym_addr = (Elf64_Sym *)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
        const char *Table_sym_str_addr = (const char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;

        for (u_int64_t i = rela_size; i < rela_glob_size; ++i)
        {
            if ((rela_addr[i].r_info & 0xffffffff) == 6)
            {
                int index = (rela_addr[i].r_info) >> 32;
                const char *str_addr = (Table_sym_str_addr + Table_sym_addr[index].st_name);
                void *address = symbolLookup(lib, (const char *)str_addr);
                Elf64_Addr *got_addr = (Elf64_Addr *)(lib->addr + rela_addr[i].r_offset);
                *got_addr = (Elf64_Addr)(address + rela_addr[i].r_addend);
            }
        }
    }
}

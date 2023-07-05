#include <elf.h>
#include <stdlib.h>
#include <stdio.h>

#include "Link.h"
#include "LoaderInternal.h"

extern void *search_symbol(LinkMap *node, const char *name);

Elf64_Addr __attribute__((visibility ("hidden"))) //this makes trampoline to call it w/o plt
runtimeResolve(LinkMap *lib, Elf64_Word reloc_entry)
{
    printf("Resolving address for entry %u\n", reloc_entry);

    Elf64_Sym *symbol_table = (Elf64_Sym *)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *string_table = (const char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Rela *rela = (Elf64_Rela *)lib->dynInfo[DT_JMPREL]->d_un.d_ptr;

    uint64_t *addr = (uint64_t *)(lib->addr + rela[reloc_entry].r_offset);
    size_t symbol_index = rela[reloc_entry].r_info >> 32;
    uint64_t reloc_type = rela[reloc_entry].r_info & 0xffffffff;
    Elf64_Sym symbol = symbol_table[symbol_index];
    const char *sym_str = string_table + symbol.st_name;
    void *fixed_address = search_symbol(lib, sym_str);
    return (*addr = (uint64_t)fixed_address + rela[reloc_entry].r_addend);
}
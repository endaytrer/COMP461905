#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "Link.h"
#include "Loader.h"
#define HIJACK(function) \
do { \
    if (strcmp(name, #function) == 0) { \
        return v_ ## function; \
    } \
} while (0)

extern void trampoline();

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

int v_vzlogx(const void *xref, int prio, const char *format, ...) {
    printf("[ZEBRA] ");
    va_list ap;
    va_start(ap, format);
    printf(format, ap);
    printf("\n");
}
void v_zlog_tls_buffer_flush() {
    fflush(stdout);
}

void v_zlog_tls_buffer_init() {
}
void v_zlog_tls_buffer_fini() {
}
// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{

    if(dep->fake)
    {
        if(!dep->fakeHandle)
            dep->fakeHandle = dlopen(dep->name, RTLD_LAZY);

        return dlsym(dep->fakeHandle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
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
    return NULL; //not this dependency
}

void *search_symbol(LinkMap *node, const char *name) {
    HIJACK(vzlogx);
    HIJACK(zlog_tls_buffer_flush);
    HIJACK(zlog_tls_buffer_init);
    HIJACK(zlog_tls_buffer_fini);
    if (node == NULL) return NULL;
    void *symbol_addr;
    if ((symbol_addr = symbolLookup(node, name)) != NULL)
        return symbol_addr;
    for (int i = 0; i < node->num_deps; i++) {
        if ((symbol_addr = search_symbol(node->deps[i], name)) != NULL)
            return symbol_addr;
    }
    return NULL;
}

void reloc_jmprel_lazy(LinkMap *lib,  Elf64_Rela *rela) {
    
    size_t reloc_size = lib->dynInfo[DT_PLTRELSZ]->d_un.d_val / sizeof(Elf64_Rela);
    uint64_t *got = (uint64_t *)lib->dynInfo[DT_PLTGOT]->d_un.d_ptr;
    got[1] = (uint64_t)lib;
    got[2] = (uint64_t)trampoline;
    for (int i = 0; i < reloc_size; i++) {
        uint64_t *addr = (uint64_t *)(lib->addr + rela[i].r_offset);
        *addr += lib->addr + rela[i].r_addend;
    }
}
void reloc_jmprel(LinkMap *lib,  Elf64_Rela *rela, Elf64_Sym *symbol_table, const char *string_table) {
    
    size_t reloc_size = lib->dynInfo[DT_PLTRELSZ]->d_un.d_val / sizeof(Elf64_Rela);
    for (int i = 0; i < reloc_size; i++) {
        uint64_t *addr = (uint64_t *)(lib->addr + rela[i].r_offset);
        size_t symbol_index = rela[i].r_info >> 32;
        Elf64_Sym symbol = symbol_table[symbol_index];
        const char *sym_str = string_table + symbol.st_name;
        void *fixed_address = search_symbol(lib, sym_str);
        *addr = (uint64_t)fixed_address + rela[i].r_addend;
    }
}

void reloc_rela(LinkMap *lib, Elf64_Rela *rela, Elf64_Sym *symbol_table, const char *string_table) {
    size_t reloc_size = lib->dynInfo[DT_RELASZ]->d_un.d_val / sizeof(Elf64_Rela);

    for (int i = 0; i < reloc_size; i++) {
        uint64_t *addr = (uint64_t *)(lib->addr + rela[i].r_offset);
        uint64_t reloc_type = ELF64_R_TYPE(rela[i].r_info);
#if defined(__aarch64__) || defined(_M_ARM64)
        if (reloc_type == R_AARCH64_GLOB_DAT) {
#else
        if (reloc_type == R_X86_64_GLOB_DAT) {
#endif
            size_t symbol_index = rela[i].r_info >> 32;
            Elf64_Sym symbol = symbol_table[symbol_index];
            const char *sym_str = string_table + symbol.st_name;
            void *fixed_address = search_symbol(lib, sym_str);
            // void *fixed_address = symbolLookup(lib, sym_str);

            *addr = (uint64_t)fixed_address;
        } else if (reloc_type == R_X86_64_RELATIVE) {
            *addr = lib->addr + rela[i].r_addend;
        } else if (reloc_type == R_X86_64_64) {
            size_t symbol_index = rela[i].r_info >> 32;
            Elf64_Sym symbol = symbol_table[symbol_index];
            const char *sym_str = string_table + symbol.st_name;
            void *fixed_address = search_symbol(lib, sym_str);
            // void *fixed_address = symbolLookup(lib, sym_str);

            *addr = (uint64_t)fixed_address + rela[i].r_addend;
        } else if (reloc_type == R_X86_64_COPY) {

            // Here I just malloc for every entry
            // TODO: use dedicated data structure for this.

            size_t symbol_index = rela[i].r_info >> 32;
            Elf64_Sym symbol = symbol_table[symbol_index];
            const char *sym_str = string_table + symbol.st_name;
            void *fixed_address = search_symbol(lib, sym_str);
            void *new_symbol = malloc(symbol.st_size);
            memcpy(new_symbol, fixed_address, symbol.st_size);
            *addr = (uint64_t)new_symbol;
        } else if (reloc_type == R_X86_64_DTPMOD64) {
            *addr = lib->tls_id;
        } else if (reloc_type == R_X86_64_TPOFF64) {
            size_t symbol_index = rela[i].r_info >> 32;
            Elf64_Sym symbol = symbol_table[symbol_index];
            *addr = (uint64_t)lib->tls_block + symbol.st_value + rela[i].r_addend;
        } else {

            // Here I just malloc for every entry
            // TODO: use thread local storage.

            printf("%s, unexpected reloc type = %d\n", lib->name, reloc_type);

            // size_t symbol_index = rela[i].r_info >> 32;
            // Elf64_Sym symbol = symbol_table[symbol_index];
            // void *new_symbol = malloc(symbol.st_size);
        }
    }
}


void RelocLibrary(LinkMap *lib, int mode)
{
    if (lib->fake) return;
    Elf64_Sym *symbol_table = (Elf64_Sym *)lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *string_table = (const char *)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    
    if (lib->dynInfo[DT_JMPREL]) {
        if (mode == BIND_NOW)
            reloc_jmprel(lib, (Elf64_Rela *)lib->dynInfo[DT_JMPREL]->d_un.d_ptr, symbol_table, string_table);
        else
            reloc_jmprel_lazy(lib, (Elf64_Rela *)lib->dynInfo[DT_JMPREL]->d_un.d_ptr);
    }
    if (lib->dynInfo[DT_RELA]) reloc_rela(lib, (Elf64_Rela *)lib->dynInfo[DT_RELA]->d_un.d_ptr, symbol_table, string_table);
    for (int i = 0; i < lib->num_deps; i++) {
        RelocLibrary(lib->deps[i], mode);
    }
}

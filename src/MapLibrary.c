#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <dlfcn.h>

#define MAP_ANONYMOUS 0x20

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))
#define ALIGNED_SIZE(base, size) (ALIGN_UP(base + size, getpagesize()) - ALIGN_DOWN(base, getpagesize()))
extern char *sys_path[64];

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux-x86-64.so.2",
    NULL,
};

static void setup_hash(LinkMap *l)
{
    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    memset(dyn_info, 0, (DT_GNU_HASH + 1) * sizeof(Elf64_Dyn*));
    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT_)
            dyn_info[DT_RELACOUNT] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH_)
            dyn_info[DT_GNU_HASH] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

static uint64_t num_tls_maps = 0;

LinkMap *MapLibrary(const char *libpath)
{
    /*
     * hint:
     * 
     * lib = malloc(sizeof(LinkMap));
     * 
     * foreach segment:
     * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
     *      segment_offset);
     * 
     * lib -> addr = ...;
     * lib -> dyn = ...;
     * 
     * fill_info(lib);
     * setup_hash(lib);
     * 
     * return lib;
    */
    
    LinkMap *lib = malloc(sizeof(LinkMap));
    lib->name = libpath;
    for (int j = 0; fake_so[j] != NULL; j++) {
        if (strcmp(libpath, fake_so[j]) == 0) {
            lib->fake = 1;
            lib->num_deps = 0;
            lib->fakeHandle = NULL;
            return lib;
        }
    }
    lib->fake = 0;
    int fd = -1;
    // find in path
    const int char_size = 1024;
    char *buf = malloc(char_size);
    for (int i = 0; sys_path[i] != NULL; i++) {
        memset(buf, 0, char_size);
        strcpy(buf, sys_path[i]);
        if (strlen(buf) != 0)
            strcat(buf, "/");
        strcat(buf, libpath);
        if ((fd = open(buf, O_RDONLY)) >= 0)
            break;
    }
    free(buf);
    if (fd < 0) {
        return NULL;
    }

    Elf64_Ehdr elf_header;
    read(fd, &elf_header, sizeof(Elf64_Ehdr));

    // Read programs
    Elf64_Phdr *program_headers = malloc(elf_header.e_phnum * sizeof(Elf64_Phdr));
    lseek(fd, elf_header.e_phoff, SEEK_SET);
    read(fd, program_headers, elf_header.e_phnum * sizeof(Elf64_Phdr));
    size_t total_size = 0;

    // First pass of program headers
    // Need to figure out the memory size of the library
    for (int i = 0; i < elf_header.e_phnum; i++) {
        if (program_headers[i].p_type == PT_LOAD) {
            size_t offset_size = ALIGN_UP(program_headers[i].p_vaddr + program_headers[i].p_memsz, getpagesize());
            total_size = total_size > offset_size ? total_size : offset_size;
        }
    }
    // Second pass of program headers
    // Map the data, and get RWX Permission of each page.
    void *lib_block = mmap(NULL, total_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(lib_block, 0, total_size);
    lib->addr = (uint64_t)lib_block;
    lib->size = total_size;
    lib->use_tls = false;
    size_t pagesize = getpagesize();
    size_t total_pages = total_size / pagesize;
    uint8_t *page_permissions = malloc(total_pages);
    memset(page_permissions, 0, total_pages);

    for (int i = 0; i < elf_header.e_phnum; i++) {
        switch (program_headers[i].p_type) {
            case PT_LOAD:
                int prot = 0;
                prot |= (program_headers[i].p_flags & PF_R)? PROT_READ : 0;
                prot |= (program_headers[i].p_flags & PF_W)? PROT_WRITE : 0;
                prot |= (program_headers[i].p_flags & PF_X)? PROT_EXEC : 0;

                off_t offset_aligned = ALIGN_DOWN(program_headers[i].p_offset, pagesize);
                size_t size_to_map = ALIGN_UP(program_headers[i].p_filesz + program_headers[i].p_offset, pagesize) - offset_aligned;

                void *file_block = mmap(NULL, size_to_map, PROT_READ, MAP_PRIVATE, fd, offset_aligned);
                memcpy(
                    (void *)(lib->addr + program_headers[i].p_vaddr),
                    (void *)((uint64_t)file_block + program_headers[i].p_offset - offset_aligned),
                    program_headers[i].p_filesz
                );

                off_t vaddr_aligned = ALIGN_DOWN(program_headers[i].p_vaddr, pagesize) / pagesize;
                size_t size_to_protect = ALIGN_UP(program_headers[i].p_memsz + program_headers[i].p_vaddr, pagesize) / pagesize - vaddr_aligned;

                for (off_t i = vaddr_aligned; i < vaddr_aligned + size_to_protect; i++) {
                    page_permissions[i] |= prot;
                }

                munmap(file_block, size_to_map);
                
                if (program_headers[i].p_type != PT_LOAD && program_headers[i].p_type != PT_TLS) continue;
                break;

            case PT_TLS:
                if (!lib->use_tls) {
                    lib->use_tls = true;
                    lib->tls_id = num_tls_maps++;
                }
                lib->tls_size = program_headers[i].p_memsz;
                lib->tls_align = program_headers[i].p_align;
                if (program_headers[i].p_align != 0)
                    lib->tls_first_byte_offset = program_headers[i].p_vaddr & (program_headers[i].p_align - 1);
                else 
                    lib->tls_first_byte_offset = 0;

                printf("%s Thread local storage at %p - %p, align %d\n", lib->name, program_headers[i].p_vaddr, program_headers[i].p_memsz, program_headers[i].p_align);
                break;
                
        }
    }
    // Third pass
    // protect the pages with correct permission
    for (size_t i = 0; i < total_pages; i++) {
        mprotect(
            (void *)(lib->addr + i * pagesize),
            pagesize,
            page_permissions[i]
        );
    }

    free(program_headers);
    free(page_permissions);

    // Map TLS block;
    if (lib->use_tls) {
        lib->tls_block = mmap(NULL, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("%s TLS BLOCK @ %p\n", lib->name, lib->tls_block);
    }

    // Read sections

    Elf64_Shdr *section_headers = malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
    lseek(fd, elf_header.e_shoff, SEEK_SET);
    read(fd, section_headers, elf_header.e_shnum * sizeof(Elf64_Shdr));

    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (section_headers[i].sh_type == SHT_DYNAMIC) {
            lib->dyn = (Elf64_Dyn *)(lib->addr + section_headers[i].sh_addr);
            break;
        }
    }
    free(section_headers);

    fill_info(lib);
    setup_hash(lib);
    size_t num_deps = 0;
    lib->num_deps = 0;
    for (Elf64_Dyn *dyn = lib->dyn; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag != DT_NEEDED)
            continue;
        num_deps++;
    }
    if (num_deps == 0) return lib;
    lib->deps = malloc(num_deps * sizeof(LinkMap *));
    for (Elf64_Dyn *dyn = lib->dyn; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag != DT_NEEDED)
            continue;
        const char *sym_str = (const char *)(lib->dynInfo[DT_STRTAB]->d_un.d_ptr);
        const char *libname = sym_str + dyn->d_un.d_ptr;
        LinkMap *dep = MapLibrary(libname);
        lib->deps[lib->num_deps++] = dep;
    }
    return lib;
}


void FreeLibrary(void *lib) {
    LinkMap *map = (LinkMap *)lib;

    if (!map->fake) {

        for (int i = 0; i < map->num_deps; i++)
            FreeLibrary(map->deps[i]);

        munmap((void *)map->addr, map->size);
        free(map->deps);
        if (map->use_tls)
            munmap(map->tls_block, getpagesize());
        
    }
    free(map);
}
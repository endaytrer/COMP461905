#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))
#define ALIGNED_SIZE(base, size) (ALIGN_UP(base + size, getpagesize()) - ALIGN_DOWN(base, getpagesize()))
static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

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

void *MapLibrary(const char *libpath)
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
    
    int fd;
    if ((fd = open(libpath, O_RDWR)) < 0)
        return NULL;

    Elf64_Ehdr elf_header;
    read(fd, &elf_header, sizeof(Elf64_Ehdr));
    
    // Read programs
    Elf64_Phdr *program_headers = malloc(elf_header.e_phnum * sizeof(Elf64_Phdr));
    lseek(fd, elf_header.e_phoff, SEEK_SET);
    read(fd, program_headers, elf_header.e_phnum * sizeof(Elf64_Phdr));
    uint8_t *back;
    size_t total_size = 0;
    for (int i = 0; i < elf_header.e_phnum; i++) {
        if (program_headers[i].p_type == PT_LOAD)
            total_size += ALIGNED_SIZE(program_headers[i].p_offset, program_headers[i].p_memsz);
    }
    int64_t zero_offset;
    for (int i = 0; i < elf_header.e_phnum; i++) {
        if (program_headers[i].p_type != PT_LOAD) continue;

        int prot = 0;
        prot |= (program_headers[i].p_flags & PF_R)? PROT_READ : 0;
        prot |= (program_headers[i].p_flags & PF_W)? PROT_WRITE : 0;
        prot |= (program_headers[i].p_flags & PF_X)? PROT_EXEC : 0;
        size_t aligned_size = ALIGNED_SIZE(program_headers[i].p_offset, program_headers[i].p_memsz);

        if (i == 0) {
            zero_offset = -ALIGN_DOWN(program_headers[i].p_offset, getpagesize());
            lib->addr = (uint64_t)mmap(NULL, total_size, prot, MAP_PRIVATE, fd, ALIGN_DOWN(program_headers[i].p_offset, getpagesize()));
            back = (void *)(lib->addr + aligned_size);
            continue;
        }
        back = mmap(back, aligned_size, prot, MAP_PRIVATE | MAP_FIXED, fd, ALIGN_DOWN(program_headers[i].p_offset, getpagesize()));

        back = (void *)((uint64_t)back + aligned_size);
    }
    free(program_headers);
    // Read sections

    Elf64_Shdr *section_headers = malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
    lseek(fd, elf_header.e_shoff, SEEK_SET);
    read(fd, section_headers, elf_header.e_shnum * sizeof(Elf64_Shdr));

    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (section_headers[i].sh_type == SHT_DYNAMIC) {
            lib->dyn = (Elf64_Dyn * )(lib->addr + zero_offset + section_headers[i].sh_addr);
            break;
        }
    }
    free(section_headers);

    fill_info(lib);
    setup_hash(lib);


    return lib;
}

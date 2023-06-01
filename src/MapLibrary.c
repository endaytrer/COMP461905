#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH_NEW]->d_un.d_ptr;
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

    while (dyn->d_tag != DT_NULL)
    {
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT)
            dyn_info[DT_RELACOUNT_NEW] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH)
            dyn_info[DT_GNU_HASH_NEW] = dyn;
        ++dyn;
    }
#define rebase(tag)                                 \
    do                                              \
    {                                               \
        if (dyn_info[tag])                          \
            dyn_info[tag]->d_un.d_ptr += lib->addr; \
    } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH_NEW); // DT_GNU_HASH
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

    /* Your code here */
    LinkMap *lib = malloc(sizeof(LinkMap));

    // Load ELF Header
    int fd = open(libpath, O_RDONLY);
    Elf64_Ehdr EhdrBuf;
    // lseek(fd, 0, SEEK_SET);
    read(fd, &EhdrBuf, sizeof(Elf64_Ehdr));

    int num = 0;
    void *Paddr;
    uint64_t fullsize = 0;
    // Load program header
    Elf64_Phdr *PhdrBufs = malloc(EhdrBuf.e_phnum * sizeof(Elf64_Phdr));
    lseek(fd, EhdrBuf.e_phoff, SEEK_SET);
    read(fd, PhdrBufs, EhdrBuf.e_phnum * sizeof(Elf64_Phdr));

    for (int i = 0; i < EhdrBuf.e_phnum; ++i) // find allocation space needed
    {
        // lseek(fd, EhdrBuf.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
        // read(fd, &PhdrBuf, sizeof(Elf64_Phdr));
        if (PhdrBufs[i].p_type == PT_LOAD)
        {
            fullsize += ALIGN_UP(PhdrBufs[i].p_vaddr + PhdrBufs[i].p_memsz, getpagesize()) - ALIGN_DOWN(PhdrBufs[i].p_vaddr, getpagesize());
        }
    }
    Paddr = malloc(fullsize);
    lib->addr = (uint64_t) Paddr;
    // lseek(fd, EhdrBuf.e_phoff, SEEK_SET);
    for (int i = 0; i < EhdrBuf.e_phnum; ++i)
    {
        // lseek(fd, EhdrBuf.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
        // read(fd, PhdrBuf, sizeof(Elf64_Phdr));
        if (PhdrBufs[i].p_type == PT_LOAD)
        {
            int prot = 0;
            prot |= (PhdrBufs[i].p_flags & PF_R) ? PROT_READ : 0;
            prot |= (PhdrBufs[i].p_flags & PF_W) ? PROT_WRITE : 0;
            prot |= (PhdrBufs[i].p_flags & PF_X) ? PROT_EXEC : 0;

            // if (!num) // first, get enough space
            // {
            //     lib->addr = (uint64_t)mmap(NULL, fullsize, prot, MAP_PRIVATE, fd, ALIGN_DOWN(PhdrBufs[i].p_offset, getpagesize()));
            //     Paddr = (void *)(lib->addr + ALIGN_UP(PhdrBufs[i].p_vaddr + PhdrBufs[i].p_memsz, getpagesize()) - ALIGN_DOWN(PhdrBufs[i].p_vaddr, getpagesize()));
            //     ++num;
            // }
            // else
            // {
                size_t len = ALIGN_UP(PhdrBufs[i].p_vaddr + PhdrBufs[i].p_memsz, getpagesize()) - ALIGN_DOWN(PhdrBufs[i].p_vaddr, getpagesize());
                mmap(Paddr, len, prot, MAP_FIXED | MAP_PRIVATE, fd, ALIGN_DOWN(PhdrBufs[i].p_offset, getpagesize()));
                Paddr = (void *)((uint64_t)Paddr + ALIGN_UP(PhdrBufs[i].p_vaddr + PhdrBufs[i].p_memsz, getpagesize()) - ALIGN_DOWN(PhdrBufs[i].p_vaddr, getpagesize()));
            // }
            /*if(Saddr >= PhdrBuf->p_offset && Saddr < PhdrBuf->p_offset + PhdrBuf->p_filesz)
            {
                lib->dyn = (Paddr - (ALIGN_UP(PhdrBuf->p_vaddr + PhdrBuf->p_memsz, PageSz) - ALIGN_DOWN(PhdrBuf->p_vaddr, PageSz))) + (PhdrBuf->p_offset - ALIGN_DOWN(PhdrBuf->p_offset, PageSz)) + (Saddr - PhdrBuf->p_vaddr);
            }*/
        }
    }

    // uint64_t Saddr, Soff;
    // Read segment headers
    Elf64_Shdr *ShdrBufs = malloc(EhdrBuf.e_shnum * sizeof(Elf64_Shdr));

    lseek(fd, EhdrBuf.e_shoff, SEEK_SET);
    read(fd, ShdrBufs, EhdrBuf.e_shnum * sizeof(Elf64_Shdr));

    for (int i = 0; i < EhdrBuf.e_shnum; ++i)
    {
        // lseek(fd, EhdrBuf.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        // read(fd, ShdrBuf, sizeof(Elf64_Shdr));
        if (ShdrBufs[i].sh_type == SHT_DYNAMIC)
        {
            // Saddr = ShdrBuf->sh_offset;
            lib->dyn = (Elf64_Dyn *)(ShdrBufs[i].sh_addr + lib->addr);
            break;
        }
    }

    fill_info(lib);
    setup_hash(lib);

    // free(EhdrBuf);
    // EhdrBuf = NULL;
    free(PhdrBufs);
    PhdrBufs = NULL;
    free(ShdrBufs);
    ShdrBufs = NULL;

    int fake = 1, cnt = 0;
    num = 0;
    Elf64_Dyn *dyn = lib->dyn;
    size_t dyn_size = 0;
    while (dyn->d_tag != DT_NULL)
    {
        if (dyn->d_tag == DT_RUNPATH)
        {
            fake = 0;
        }
        if (dyn->d_tag == DT_NEEDED)
        {
            ++num;
        }
        ++dyn;
        ++dyn_size;
    }

    if (num)
    {
        lib->searchList = malloc(dyn_size * sizeof(LinkMap *));
        // lib->searchList = malloc(sizeof(LinkMap));
        const char *Table_sym_str_addr = (const char *)(lib->dynInfo[DT_STRTAB]->d_un.d_ptr);
        char *lib_name = (char *)(lib->dynInfo[DT_NEEDED]->d_un.d_ptr + Table_sym_str_addr);
        dyn = lib->dyn;

        // while (dyn->d_tag != DT_NULL)
        for (int i = 0; i < dyn_size; i++)
        {
            if (dyn[i].d_tag == DT_NEEDED)
            {
                if (fake)
                {
                    lib->searchList[cnt] = malloc(sizeof(LinkMap));
                    lib->searchList[cnt]->name = lib_name;
                    lib->searchList[cnt++]->fake = 1;
                }
                else
                {
                    char path[] = "./test_lib/";
                    int len_lib = strlen(lib_name), len_path = strlen(path);
                    char *file = malloc((len_lib + len_path + 1) * sizeof(char));
                    strcpy(file, path);
                    strcat(file, lib_name);
                    lib->searchList[cnt] = MapLibrary(file);
                    lib->searchList[cnt++]->name = file;
                }
            }
        }
    }

    return lib;
}

/*
 * Copyright (c) 2015 Stefan Kristiansson
 * Based on arch/arm/arm/mmu.c
 * Copyright (c) 2008-2014 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <trace.h>
#include <debug.h>
#include <err.h>
#include <string.h>
#include <arch/mmu.h>
#include <arch/or1k.h>
#include <arch/or1k/mmu.h>
#include <arch/or1k/defines.h>
#include <arch/aspace.h>
#include <kernel/vm.h>
#include <assert.h>

#define LOCAL_TRACE 1

#if WITH_KERNEL_VM

pte_t or1k_kernel_translation_table[256] __ALIGNED(8192) __SECTION(".bss.prebss.translation_table");

void or1k_invalidate_tlb(vaddr_t vaddr, uint count)
{
    /* Pessimistic tlb invalidation, which rather invalidate too much.
     * TODO: make it more precise. */

    uint32_t dmmucfgr = mfspr(OR1K_SPR_SYS_DMMUCFGR_ADDR);
    uint32_t immucfgr = mfspr(OR1K_SPR_SYS_IMMUCFGR_ADDR);
    uint32_t num_dtlb_ways = OR1K_SPR_SYS_DMMUCFGR_NTW_GET(dmmucfgr) + 1;
    uint32_t num_dtlb_sets = 1 << OR1K_SPR_SYS_DMMUCFGR_NTS_GET(dmmucfgr);
    uint32_t num_itlb_ways = OR1K_SPR_SYS_IMMUCFGR_NTW_GET(immucfgr) + 1;
    uint32_t num_itlb_sets = 1 << OR1K_SPR_SYS_IMMUCFGR_NTS_GET(immucfgr);
    uint32_t offs;

    for (; count; count--) {
        offs = (vaddr >> PAGE_SIZE_SHIFT) & (num_dtlb_sets-1);
        switch (num_dtlb_ways) {
            case 4:
                mtspr_off(0, OR1K_SPR_DMMU_DTLBW_MR_ADDR(3, offs), 0);
                break;
            case 3:
                mtspr_off(0, OR1K_SPR_DMMU_DTLBW_MR_ADDR(2, offs), 0);
                break;
            case 2:
                mtspr_off(0, OR1K_SPR_DMMU_DTLBW_MR_ADDR(1, offs), 0);
                break;
            case 1:
                mtspr_off(0, OR1K_SPR_DMMU_DTLBW_MR_ADDR(0, offs), 0);
                break;
        }

        offs = (vaddr >> PAGE_SIZE_SHIFT) & (num_itlb_sets-1);
        switch (num_itlb_ways) {
            case 4:
                mtspr_off(0, OR1K_SPR_IMMU_ITLBW_MR_ADDR(3, offs), 0);
                break;
            case 3:
                mtspr_off(0, OR1K_SPR_IMMU_ITLBW_MR_ADDR(2, offs), 0);
                break;
            case 2:
                mtspr_off(0, OR1K_SPR_IMMU_ITLBW_MR_ADDR(1, offs), 0);
                break;
            case 1:
                mtspr_off(0, OR1K_SPR_IMMU_ITLBW_MR_ADDR(0, offs), 0);
                break;
        }
        vaddr += PAGE_SIZE;
    }
}

status_t arch_mmu_query(arch_aspace_t *aspace, vaddr_t vaddr, paddr_t *paddr, uint *flags)
{
    pte_t pte;
    uint index = vaddr / SECTION_SIZE;
    static uint32_t vmask = SECTION_SIZE-1;
    pte = aspace->tt_virt[index];

    if (!(pte_val(pte) & OR1K_MMU_PG_PRESENT))
        return ERR_NOT_FOUND;

    /* not a l1 entry */
    if (!(pte_val(pte) & OR1K_MMU_PG_L)) {
        uint32_t *l2_table = paddr_to_kvaddr(pte_val(pte) & ~OR1K_MMU_PG_FLAGS_MASK);
        index = (vaddr % SECTION_SIZE) / PAGE_SIZE;
        pte_val(pte) = l2_table[index];
        vmask = PAGE_SIZE-1;
    }

    if (paddr)
        *paddr = (pte_val(pte) & ~OR1K_MMU_PG_FLAGS_MASK) | (vaddr & vmask);

    if (flags) {
        *flags = 0;
        if (pte_val(pte) & OR1K_MMU_PG_U)
            *flags |= ARCH_MMU_FLAG_PERM_USER;
        if (!(pte_val(pte) & OR1K_MMU_PG_X))
            *flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;
        if (!(pte_val(pte) & OR1K_MMU_PG_W))
            *flags |= ARCH_MMU_FLAG_PERM_RO;
        if (pte_val(pte) & OR1K_MMU_PG_CI)
            *flags |= ARCH_MMU_FLAG_UNCACHED;
    }

    return NO_ERROR;
}

int arch_mmu_unmap(arch_aspace_t *aspace, vaddr_t vaddr, uint count)
{
    LTRACEF("vaddr = 0x%lx, count = %d\n", vaddr, count);

    if (!IS_PAGE_ALIGNED(vaddr))
        return ERR_INVALID_ARGS;

    uint unmapped = 0;
    while (count) {
        uint index = vaddr / SECTION_SIZE;
        pte_t pte = aspace->tt_virt[index];
        if (!(pte_val(pte) & OR1K_MMU_PG_PRESENT)) {
            vaddr += PAGE_SIZE;
            count--;
            continue;
        }
        /* Unmapping of l2 tables is not implemented (yet) */
        if (!(pte_val(pte) & OR1K_MMU_PG_L) || !IS_ALIGNED(vaddr, SECTION_SIZE) || count < SECTION_SIZE / PAGE_SIZE)
            PANIC_UNIMPLEMENTED;

        pte_val(aspace->tt_virt[index]) = 0;
        or1k_invalidate_tlb(vaddr, SECTION_SIZE / PAGE_SIZE);
        vaddr += SECTION_SIZE;
        count -= SECTION_SIZE / PAGE_SIZE;
        unmapped += SECTION_SIZE / PAGE_SIZE;
    }

    return unmapped;
}

int arch_mmu_map(arch_aspace_t *aspace, vaddr_t vaddr, paddr_t paddr, uint count, uint flags)
{
    uint l1_index;
    pte_t pte;
    uint32_t arch_flags = 0;

    LTRACEF("vaddr = 0x%lx, paddr = 0x%lx, count = %d, flags = 0x%x\n", vaddr, paddr, count, flags);

    if (!IS_PAGE_ALIGNED(vaddr) || !IS_PAGE_ALIGNED(paddr))
        return ERR_INVALID_ARGS;

    if (flags & ARCH_MMU_FLAG_PERM_USER)
        arch_flags |= OR1K_MMU_PG_U;
    if (!(flags & ARCH_MMU_FLAG_PERM_NO_EXECUTE))
        arch_flags |= OR1K_MMU_PG_X;
    if (flags & ARCH_MMU_FLAG_CACHE_MASK)
        arch_flags |= OR1K_MMU_PG_CI;
    if (!(flags & ARCH_MMU_FLAG_PERM_RO))
        arch_flags |= OR1K_MMU_PG_W;

    uint mapped = 0;
    while (count) {
        l1_index = vaddr / SECTION_SIZE;
        if (IS_ALIGNED(vaddr, SECTION_SIZE) &&
                IS_ALIGNED(paddr, SECTION_SIZE) &&
                count >= SECTION_SIZE / PAGE_SIZE) {
            pte_val(aspace->tt_virt[l1_index]) = (paddr & ~(SECTION_SIZE-1))
                    | arch_flags | OR1K_MMU_PG_PRESENT | OR1K_MMU_PG_L;
            count -= SECTION_SIZE / PAGE_SIZE;
            mapped += SECTION_SIZE / PAGE_SIZE;
            vaddr += SECTION_SIZE;
            paddr += SECTION_SIZE;
            continue;
        }

        uint32_t *l2_table;

        pte = aspace->tt_virt[l1_index];

        /* FIXME: l1 already mapped as a section */
        if ((pte_val(pte) & OR1K_MMU_PG_PRESENT) && (pte_val(pte) & OR1K_MMU_PG_L))
            PANIC_UNIMPLEMENTED;

        if (pte_val(pte) & OR1K_MMU_PG_PRESENT) {
            l2_table = paddr_to_kvaddr(pte_val(pte) & ~OR1K_MMU_PG_FLAGS_MASK);
            LTRACEF("l2_table at %p\n", l2_table);
        } else {
            l2_table = pmm_alloc_kpage();
            if (!l2_table) {
                TRACEF("failed to allocate pagetable\n");
                return mapped;
            }

            memset(l2_table, 0, PAGE_SIZE);
            paddr_t l2_pa = vaddr_to_paddr(l2_table);
            LTRACEF("allocated pagetable at %p, pa 0x%lx\n", l2_table, l2_pa);
            pte_val(aspace->tt_virt[l1_index]) = l2_pa | arch_flags | OR1K_MMU_PG_PRESENT;
        }

        uint l2_index = (vaddr % SECTION_SIZE) / PAGE_SIZE;

        LTRACEF("l2_index = 0x%x, vaddr = 0x%lx, paddr = 0x%lx\n", l2_index, vaddr, paddr);
        l2_table[l2_index] = paddr | arch_flags | OR1K_MMU_PG_PRESENT | OR1K_MMU_PG_L;

        count--;
        mapped++;
        vaddr += PAGE_SIZE;
        paddr += PAGE_SIZE;
    }

    return mapped;
}

status_t arch_mmu_init_aspace(arch_aspace_t *aspace, vaddr_t base, size_t size, uint flags)
{
    LTRACEF("aspace %p, base 0x%lx, size 0x%zx, flags 0x%x\n", aspace, base, size, flags);

    DEBUG_ASSERT(aspace);

    /* validate that the base + size is sane and doesn't wrap */
    DEBUG_ASSERT(size > PAGE_SIZE);
    DEBUG_ASSERT(base + size - 1 > base);

    aspace->flags = flags;
    if (flags & ARCH_ASPACE_FLAG_KERNEL) {
        /* at the moment we can only deal with address spaces as globally defined */
        DEBUG_ASSERT(base == ~0UL << MMU_KERNEL_SIZE_SHIFT);
        DEBUG_ASSERT(size == 1UL << MMU_KERNEL_SIZE_SHIFT);

        aspace->base = base;
        aspace->size = size;
        aspace->tt_virt = or1k_kernel_translation_table;
        aspace->tt_phys = vaddr_to_paddr(aspace->tt_virt);
    } else {
        //DEBUG_ASSERT(base >= 0);
        DEBUG_ASSERT(base + size <= 1UL << MMU_USER_SIZE_SHIFT);

        aspace->base = base;
        aspace->size = size;

        pte_t *va = pmm_alloc_kpages(1, NULL);
        if (!va)
            return ERR_NO_MEMORY;

        aspace->tt_virt = va;
        aspace->tt_phys = vaddr_to_paddr(aspace->tt_virt);

        /* zero the top level translation table */
        /* XXX remove when PMM starts returning pre-zeroed pages */
        memset(aspace->tt_virt, 0, PAGE_SIZE);
    }

    LTRACEF("tt_phys 0x%lx tt_virt %p\n", aspace->tt_phys, aspace->tt_virt);

    return NO_ERROR;
}

status_t arch_mmu_destroy_aspace(arch_aspace_t *aspace)
{
    LTRACEF("aspace %p\n", aspace);

    DEBUG_ASSERT(aspace);
    DEBUG_ASSERT((aspace->flags & ARCH_ASPACE_FLAG_KERNEL) == 0);

    return NO_ERROR;
}

void arch_mmu_context_switch(arch_aspace_t *aspace)
{
    LTRACEF("switch aspace %p\n", aspace);

    // Nothing to do as we have no hardware MMU
}


#endif /* WITH_KERNEL_VM */

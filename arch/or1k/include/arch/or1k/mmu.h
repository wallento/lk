/*
 * Copyright (c) 2015-2016 Stefan Kristiansson, Stefan Wallentowitz, Google Inc.
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
#pragma once

typedef struct {
    uint32_t pte;
} pte_t;

#define pte_val(p) ((p).pte)

#define IFTE(c,t,e) (!!(c) * (t) | !(c) * (e))
#define NBITS01(n)      IFTE(n, 1, 0)
#define NBITS02(n)      IFTE((n) >>  1,  1 + NBITS01((n) >>  1), NBITS01(n))
#define NBITS04(n)      IFTE((n) >>  2,  2 + NBITS02((n) >>  2), NBITS02(n))
#define NBITS08(n)      IFTE((n) >>  4,  4 + NBITS04((n) >>  4), NBITS04(n))
#define NBITS16(n)      IFTE((n) >>  8,  8 + NBITS08((n) >>  8), NBITS08(n))
#define NBITS(n)        IFTE((n) >> 16, 16 + NBITS16((n) >> 16), NBITS16(n))

#ifndef MMU_KERNEL_SIZE_SHIFT
#define KERNEL_ASPACE_BITS (NBITS(0xffffffff-KERNEL_ASPACE_BASE))
#define KERNEL_BASE_BITS (NBITS(0xffffffff-KERNEL_BASE))
#if KERNEL_BASE_BITS > KERNEL_ASPACE_BITS
#define KERNEL_ASPACE_BITS KERNEL_BASE_BITS /* KERNEL_BASE should not be below KERNEL_ASPACE_BASE */
#endif

#if KERNEL_ASPACE_BITS < 25
#define MMU_KERNEL_SIZE_SHIFT (25)
#else
#define MMU_KERNEL_SIZE_SHIFT (KERNEL_ASPACE_BITS)
#endif
#endif

#ifndef MMU_USER_SIZE_SHIFT
#define MMU_USER_SIZE_SHIFT 32
#endif

#ifndef MMU_IDENT_SIZE_SHIFT
#define MMU_IDENT_SIZE_SHIFT 24 /* TODO */
#endif

#define MMU_KERNEL_PAGE_SIZE_SHIFT      (PAGE_SIZE_SHIFT)
#define MMU_USER_PAGE_SIZE_SHIFT        (USER_PAGE_SIZE_SHIFT)

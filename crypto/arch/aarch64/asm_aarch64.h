/*
 * Copyright (c) 2026 Brent Cook <bcook@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Portability macros for aarch64 assembly
 */

#ifdef __APPLE__

#define ASM_SYMBOL(name)         _##name
#define ASM_TYPE_FUNCTION(name)  /* nothing */
#define ASM_TYPE_OBJECT(name)    /* nothing */
#define ASM_SIZE(name)           /* nothing */
#define ASM_SECTION_TEXT         .text
#define ASM_SECTION_RODATA       .section __TEXT,__const
#define ASM_PAGE(sym)            sym##@PAGE
#define ASM_PAGEOFF(sym)         sym##@PAGEOFF

#else /* ELF */

#define ASM_SYMBOL(name)         name
#define ASM_TYPE_FUNCTION(name)  .type name,@function
#define ASM_TYPE_OBJECT(name)    .type name,@object
#define ASM_SIZE(name)           .size name,.-name
#define ASM_SECTION_TEXT         .section .text
#define ASM_SECTION_RODATA       .section .rodata
#define ASM_PAGE(sym)            sym
#define ASM_PAGEOFF(sym)         :lo12:sym

#endif

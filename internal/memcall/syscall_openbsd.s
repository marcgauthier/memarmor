// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../thirdparty/xsys/LICENSE.

#include "textflag.h"

#define PTR_SIZE 8
#ifdef GOARCH_386
#undef PTR_SIZE
#define PTR_SIZE 4
#endif
#ifdef GOARCH_arm
#undef PTR_SIZE
#define PTR_SIZE 4
#endif

#ifdef GOARCH_ppc64
#define LIBC_CALL(symbol) CALL symbol(SB); RET
#else
#define LIBC_CALL(symbol) JMP symbol(SB)
#endif

TEXT mlock<>(SB),NOSPLIT,$0-0
	LIBC_CALL(libc_mlock)
GLOBL ·mlockTrampoline(SB), RODATA, $PTR_SIZE
DATA ·mlockTrampoline(SB)/PTR_SIZE, $mlock<>(SB)

TEXT munlock<>(SB),NOSPLIT,$0-0
	LIBC_CALL(libc_munlock)
GLOBL ·munlockTrampoline(SB), RODATA, $PTR_SIZE
DATA ·munlockTrampoline(SB)/PTR_SIZE, $munlock<>(SB)

TEXT mprotect<>(SB),NOSPLIT,$0-0
	LIBC_CALL(libc_mprotect)
GLOBL ·mprotectTrampoline(SB), RODATA, $PTR_SIZE
DATA ·mprotectTrampoline(SB)/PTR_SIZE, $mprotect<>(SB)

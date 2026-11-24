// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by the BSD-style license in
// ../../thirdparty/xsys/LICENSE.

#include "textflag.h"

TEXT poll<>(SB),NOSPLIT,$0-0
	JMP libc_poll(SB)
GLOBL ·pollTrampoline(SB), RODATA, $8
DATA ·pollTrampoline(SB)/8, $poll<>(SB)

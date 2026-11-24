# Third-party licenses

This package is a Go port based on the AES-GCM-SIV C implementation in
[AWS-LC](https://github.com/aws/aws-lc). The Go code in this repository
was written from scratch for this port, following the structure and
behavior of the AWS-LC sources listed below. This package itself is
licensed under the Apache License 2.0 (see LICENSE); the original
sources retain their own licenses, reproduced here.

## AWS-LC AES-GCM-SIV implementation (ISC License)

Source files (as of AWS-LC commit
`79015aed87809a4db07745e8aa316fc8ef7c3784`, 2026-11-23):

- `crypto/cipher_extra/e_aesgcmsiv.c`
  — `Copyright (c) 2017, Google Inc.`, `SPDX-License-Identifier: ISC`.
  Ported as `gcmsiv.go` (key derivation, tag computation, counter mode).
- `crypto/fipsmodule/modes/polyval.c`
  — `Copyright (c) 2016, Google Inc.`, `SPDX-License-Identifier: ISC`.
  Its POLYVAL-via-GHASH approach is mirrored by the independent
  cross-check in `gcmsiv_test.go`.
- `crypto/fipsmodule/modes/gcm_nohw.c`
  (BoringSSL-derived, ISC licensed). The table-free POLYVAL dot product
  in `polyval.go` uses the carryless-multiplication technique from this
  file, reimplemented from the underlying mathematics.

AWS-LC is a fork of BoringSSL; Google-authored BoringSSL code of this
vintage is licensed under the ISC License. The full AWS-LC license file
is at <https://github.com/aws/aws-lc/blob/main/LICENSE>.

```
Copyright (c) 2016, Google Inc.
Copyright (c) 2017, Google Inc.

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
```

## Test vectors

- `testdata/rfc8452_aes128.txt` and `testdata/rfc8452_aes256.txt` are
  verbatim copies of AWS-LC's `crypto/cipher_extra/test/aes_128_gcm_siv_tests.txt`
  and `aes_256_gcm_siv_tests.txt`, which collect the test vectors from
  RFC 8452 (Appendices C.1–C.3 and the Section 8 worked example) plus
  reference-code random vectors. RFC content is subject to the IETF
  Trust Legal Provisions (<https://trustee.ietf.org/license-info>).
- `testdata/wycheproof_aes_gcm_siv.json` is from Project Wycheproof
  (`third_party/wycheproof_testvectors/aes_gcm_siv_test.json` in AWS-LC),
  which AWS-LC identifies as `SPDX-License-Identifier: Apache-2.0`.

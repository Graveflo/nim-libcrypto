import mdigest

export mdigest

type
  ShaDigest* = ptr object of MessageDigest
  MD2 = ptr object of ShaDigest
  MD5 = ptr object of ShaDigest
  Sha = ptr object of ShaDigest
  Sha1 = ptr object of ShaDigest
  Sha244* = ptr object of ShaDigest
  Sha256* = ptr object of ShaDigest
  Sha384* = ptr object of ShaDigest
  Sha512* = ptr object of ShaDigest

  ShaKind* = enum
    sha1
    sha224
    sha256
    sha384
    sha512

proc EVP_sha224*(): MessageDigest {.importc, header: "<openssl/evp.h>", nodecl.}
proc EVP_sha256*(): MessageDigest {.importc, nodecl.}
proc EVP_sha512_224*(): MessageDigest {.importc, nodecl.}
proc EVP_sha512_256*(): MessageDigest {.importc, nodecl.}
proc EVP_sha384*(): MessageDigest {.importc, nodecl.}
proc EVP_sha512*(): MessageDigest {.importc, nodecl.}

proc C_SHA1*(data: cstring, len: csize_t, md: cstring): cstring {.importc: "SHA1".}
proc C_SHA224*(data: cstring, len: csize_t, md: cstring): cstring {.importc: "SHA224".}
proc C_SHA256*(data: cstring, len: csize_t, md: cstring): cstring {.importc: "SHA256".}
proc C_SHA384*(data: cstring, len: csize_t, md: cstring): cstring {.importc: "SHA384".}
proc C_SHA512*(data: cstring, len: csize_t, md: cstring): cstring {.importc: "SHA512".}

{.push deprecated.}
type
  C_SHA_CTX* {.importc: "const SHA_CTX", header: "<openssl/evp.h>".} = object
  C_SHA256_CTX* {.importc: "const SHA256_CTX".} = object
  C_SHA512_CTX* {.importc: "const SHA512_CTX".} = object
  ShaCtx* = ptr C_SHA_CTX
  Sha256Ctx* = ptr C_SHA_CTX
  Sha512Ctx* = ptr C_SHA_CTX

proc SHA1_Init*(c: ShaCtx): cint {.importc.}
proc SHA1_Update*(c: ShaCtx, data: pointer, len: csize_t): cint {.importc.}
proc SHA1_Final*(c: ShaCtx, data: pointer): cint {.importc.}

proc SHA224_Init*(c: Sha256Ctx): cint {.importc.}
proc SHA224_Update*(c: Sha256Ctx, data: pointer, len: csize_t): cint {.importc.}
proc SHA224_Final*(c: Sha256Ctx, data: pointer): cint {.importc.}

proc SHA256_Init*(c: Sha256Ctx): cint {.importc.}
proc SHA256_Update*(c: Sha256Ctx, data: pointer, len: csize_t): cint {.importc.}
proc SHA256_Final*(c: Sha256Ctx, data: pointer): cint {.importc.}

proc SHA384_Init*(c: Sha512Ctx): cint {.importc.}
proc SHA384_Update*(c: Sha512Ctx, data: pointer, len: csize_t): cint {.importc.}
proc SHA384_Final*(c: Sha512Ctx, data: pointer): cint {.importc.}

proc SHA512_Init*(c: Sha512Ctx): cint {.importc.}
proc SHA512_Update*(c: Sha512Ctx, data: pointer, len: csize_t): cint {.importc.}
proc SHA512_Final*(c: Sha512Ctx, data: pointer): cint {.importc.}
{.pop.}

proc digestSha1*[T](data: openArray[T]): array[20, byte] =
  let rlen = data.len * sizeof(T)
  discard C_SHA1(cast[cstring](data.addr), rlen.csize_t, cast[cstring](result.addr))

proc digestSha224*[T](data: openArray[T]): array[28, byte] =
  let rlen = data.len * sizeof(T)
  discard C_SHA224(cast[cstring](data.addr), rlen.csize_t, cast[cstring](result.addr))

proc digestSha256*[T](data: openArray[T]): array[32, byte] =
  let rlen = data.len * sizeof(T)
  discard C_SHA256(cast[cstring](data.addr), rlen.csize_t, cast[cstring](result.addr))

proc digestSha384*[T](data: openArray[T]): array[48, byte] =
  let rlen = data.len * sizeof(T)
  discard C_SHA384(cast[cstring](data.addr), rlen.csize_t, cast[cstring](result.addr))

proc digestSha512*[T](data: openArray[T]): array[64, byte] =
  let rlen = data.len * sizeof(T)
  discard C_SHA512(cast[cstring](data.addr), rlen.csize_t, cast[cstring](result.addr))

proc digest*(K: static ShaKind, data: openArray[byte | char]): string =
  case K
  of sha256:
    result = digestSha256(data).toHex
  of sha1:
    result = digestSha1(data).toHex
  of sha224:
    result = digestSha224(data).toHex
  of sha384:
    result = digestSha384(data).toHex
  of sha512:
    result = digestSha512(data).toHex

proc digest*(K: static ShaKind, data: string): string =
  digest(K, data.toOpenArray)

proc newDigest*[T: ShaDigest](t: typedesc[T]): DigestPack[T] =
  when (T) is Sha244:
    result.md = EVP_sha224()
  elif T is Sha256:
    result.md = EVP_sha256()
  elif T is Sha384:
    result.md = EVP_sha384()
  elif T is Sha512:
    result.md = EVP_sha512()
  else:
    {.error, "algo not hooked up".}
  result.ctx = EVP_MD_CTX_new()
  discard EVP_DigestInit_ex(result.ctx, result.md, nil)

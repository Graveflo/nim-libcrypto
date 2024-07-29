import evp

type
  EVP_MD_CTX* {.importc: "EVP_MD_CTX", header: "<openssl/evp.h>", nodecl.} = object
  EVP_MD* {.importc: "EVP_MD", header: "<openssl/evp.h>", inheritable.} = object

  MessageDigest* = ptr EVP_MD
  DigestContext* = ptr EVP_MD_CTX

  DigestPack*[T] = object
    md*: MessageDigest
    ctx*: DigestContext

proc EVP_MD_free*(md: MessageDigest) {.importc, nodecl.}
proc EVP_MD_CTX_free*(ctx: DigestContext) {.importc, nodecl.}
proc EVP_MD_CTX_dup*(ctx: DigestContext): DigestContext {.importc, nodecl.}
# https://www.openssl.org/docs/man1.0.2/man3/EVP_MD_CTX_init.html
# https://www.openssl.org/docs/man3.1/man3/EVP_DigestUpdate.html
proc EVP_MD_up_ref*(md: MessageDigest): cint {.importc, nodecl.}
proc EVP_MD_get_size*(ctx: MessageDigest): cint {.importc, nodecl.}

proc EVP_MD_CTX_new*(): DigestContext {.importc, nodecl.}
proc EVP_MD_CTX_create*(): DigestContext {.importc, nodecl, nodecl.}
proc EVP_MD_CTX_init*(ctx: DigestContext) {.importc, nodecl.}
proc EVP_MD_CTX_reset*(ctx: DigestContext): cint {.importc, nodecl.}
proc EVP_Digest*(
  data: pointer,
  count: csize_t,
  outdata: pointer,
  outLen: ptr cuint,
  md: MessageDigest,
  engine: Engine,
): cint {.importc.}

proc EVP_DigestInit*(ctx: DigestContext, t: MessageDigest): cint {.importc, nodecl.}
proc EVP_DigestInit_ex*(
  ctx: DigestContext, t: MessageDigest, egine: Engine
): cint {.importc, nodecl.}

proc EVP_DigestUpdate*(
  ctx: DigestContext, md: pointer, s: csize_t
): cint {.importc, nodecl.}
  # should change this to free for refcount https://www.openssl.org/docs/man3.1/man3/EVP_MD_CTX_free.html

proc EVP_DigestFinal*(
  ctx: DigestContext, md: pointer, s: ptr cuint
): cint {.importc, nodecl.}

proc digestSize*(md: MessageDigest): int =
  EVP_MD_get_size(md).int

proc update*(p: var DigestPack, a: pointer, length: int) =
  discard EVP_DigestUpdate(p.ctx, a, length.c_sizet)

proc update*[T](p: var DigestPack, a: openArray[T]) =
  discard EVP_DigestUpdate(p.ctx, a[0].addr, (sizeof(T) * a.len).c_sizet)

proc update*(p: var DigestPack, a: string) =
  update(p, a.toOpenArray)

proc finalUpdate*(p: sink DigestPack, a: pointer, offset = 0) =
  discard EVP_DigestFinal(p.ctx, a, nil)

proc finalUpdate*[T](p: sink DigestPack, a: openArray[T]) =
  when not defined(danger):
    if a.len * sizeof(T) > p.md.digestSize:
      raise newException(RangeDefect)
  discard EVP_DigestFinal(p.ctx, a, nil)

proc digest*[T](p: sink DigestPack[T]): seq[byte] {.gcsafe.} =
  result.setLen(p.md.digestSize)
  discard EVP_DigestFinal(p.ctx, result[0].addr, nil)

proc reset*(p: var DigestPack) =
  discard p.ctx.EVP_MD_CTX_reset()

proc realloc*(p: var DigestPack) =
  reset(p)
  discard EVP_DigestInit_ex(p.ctx, p.md, nil)

proc newDigest*[T: MessageDigest](t: typedesc[T]): DigestPack[T] =
  {.error: "Digest type not implemented".}

proc `=destroy`*[T](x: DigestPack[T]) =
  if x.md != nil:
    EVP_MD_free(x.md)
  if x.ctx != nil:
    EVP_MD_CTX_free(x.ctx)

proc `=copy`*[T](y: var DigestPack[T], x: DigestPack[T]) =
  `=destroy`(y)
  `=wasMoved`(y)
  if x.md != nil:
    discard EVP_MD_up_ref(x.md)
    y.md = x.md
  if x.ctx != nil:
    y.ctx = EVP_MD_CTX_dup(x.ctx)

proc `=dup`*[T](x: DigestPack[T]): DigestPack[T] =
  if x.md != nil:
    discard EVP_MD_up_ref(x.md)
    result.md = x.md
  if x.ctx != nil:
    result.ctx = EVP_MD_CTX_dup(x.ctx)

proc `=wasMoved`*[T](x: var DigestPack[T]) {.noSideEffect.} =
  x.ctx = nil
  x.md = nil

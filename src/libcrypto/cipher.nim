import std/[typetraits, strformat]
import faststreams/[buffers, inputs, outputs]
import support, evp

type
  C_EVP_CIPHER* {.importc: "const EVP_CIPHER", header: "<openssl/evp.h>", inheritable.} = object
  C_EVP_CIPHER_CTX* {.importc: "EVP_CIPHER_CTX", header: "<openssl/evp.h>".} = object
  EvpCipher* = ptr C_EVP_CIPHER
  EvpCipherContext* = ptr C_EVP_CIPHER_CTX

type
  EvpCipherSub =
    concept x
        EvpCipher(x)
  CipherMode* = enum
    Encrypt
    Decrypt

  CipherModeType[T: static CipherMode] =
    concept x
        x == T

  CipherPack*[T: EvpCipherSub, M: static CipherMode] = object
    cipher*: EvpCipher
    ctx*: EvpCipherContext

proc orPanick*(body: cint) =
  if body != LIBCRYPTO_SUCCESS:
    raise newException(CatchableError, "lib crypto error")

proc EVP_CIPHER_CTX_new*(): EvpCipherContext {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_reset*(ctx: EvpCipherContext) {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_dup*(
  ctx: EvpCipherContext
): EvpCipherContext {.importc, header: "<openssl/evp.h>".}

proc EVP_CIPHER_CTX_cleanup*(
  ctx: EvpCipherContext
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_CIPHER_up_ref*(ctx: EvpCipher): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_free*(ctx: EvpCipher) {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_CTX_free*(ctx: EvpCipherContext) {.importc, header: "<openssl/evp.h>".}
proc EVP_CIPHER_get_key_length*(
  cipher: EvpCipher
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_CIPHER_get_iv_length*(
  cipher: EvpCipher
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_EncryptInit_ex*(
  ctx: EvpCipherContext, cipher: EvpCipher, engine: Engine, key: pointer, iv: pointer
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_DecryptInit_ex*(
  ctx: EvpCipherContext, cipher: EvpCipher, engine: Engine, key: pointer, iv: pointer
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_EncryptUpdate*(
  ctx: EvpCipherContext, output: pointer, outlen: ptr cint, input: pointer, inlen: cint
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_EncryptFinal_ex*(
  ctx: EvpCipherContext, output: pointer, outlen: ptr cint
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_DecryptUpdate*(
  ctx: EvpCipherContext, output: pointer, outlen: ptr cint, input: pointer, inlen: cint
): cint {.importc, header: "<openssl/evp.h>".}

proc EVP_DecryptFinal_ex*(
  ctx: EvpCipherContext, output: pointer, outlen: ptr cint
): cint {.importc, header: "<openssl/evp.h>".}

proc cipherMode*(x: CipherPack): CipherMode =
  x.typeof.genericParams.get(1).value

proc newCommon*(pack: var CipherPack, key, iv: pointer) =
  pack.ctx = EVP_CIPHER_CTX_new()
  case pack.cipherMode
  of Encrypt:
    orPanick:
      EVP_EncryptInit_ex(pack.ctx, pack.cipher, nil, key, iv)
  of Decrypt:
    orPanick:
      EVP_DecryptInit_ex(pack.ctx, pack.cipher, nil, key, iv)

proc rinse*(pack: var CipherPack, key, iv: pointer) =
  orPanick:
    pack.ctx.EVP_CIPHER_CTX_cleanup()
  orPanick:
    pack.ctx.EVP_CIPHER_CTX_free()
  newCommon(pack, key, iv)

proc reuseCipher*[T, M](
    pack: CipherPack[T, M], mode: static CipherMode, key, iv: pointer
): CipherPack[T, mode] =
  result.cipher = pack.cipher
  orPanick:
    EVP_CIPHER_up_ref(pack.cipher)
  newCommon(result, key, iv)

proc reuseCipher*[T, M](
    pack: CipherPack[T, M], mode: static CipherMode, key: pointer
): CipherPack[T, mode] =
  reuseCipher(pack, mode, key, nil)

proc `=destroy`*[T, K](x: CipherPack[T, K]) =
  if x.cipher != nil:
    EVP_CIPHER_free(x.cipher)
  if x.ctx != nil:
    discard EVP_CIPHER_CTX_cleanup(x.ctx)
    EVP_CIPHER_CTX_free(x.ctx)

proc `=copy`*[T, K](y: var CipherPack[T, K], x: CipherPack[T, K]) =
  `=destroy`(y)
  `=wasMoved`(y)
  if x.cipher != nil:
    discard x.cipher.EVP_CIPHER_up_ref()
    y.cipher = x.cipher
  if x.ctx != nil:
    y.ctx = EVP_CIPHER_CTX_dup(x.ctx)

proc `=dup`*[T, K](x: CipherPack[T, K]): CipherPack[T, K] =
  if x.cipher != nil:
    discard x.cipher.EVP_CIPHER_up_ref()
    result.cipher = x.cipher
  if x.ctx != nil:
    result.ctx = EVP_CIPHER_CTX_dup(x.ctx)

proc `=wasMoved`*[T, K](x: var CipherPack[T, K]) =
  x.ctx = nil
  x.cipher = nil

proc encryptInPlace*[T: EvpCipherSub](
    pack: sink CipherPack[T, Encrypt], buffer: openArray[byte | char], length: int
): int =
  var outLen = buffer.len.cint
  var finalSize = 0
  orPanick:
    pack.ctx.EVP_EncryptUpdate(buffer[0].addr, outLen.addr, buffer[0].addr, length.cint)
  finalSize += outLen.int
  if finalSize < buffer.len: # heres hoping alignment is messed up
    orPanick:
      pack.ctx.EVP_EncryptFinal_ex(buffer[finalSize].addr, outLen.addr)
  finalSize += outLen
  return finalSize

proc basicEncrypt*[T: EvpCipherSub](
    pack: sink CipherPack[T, Encrypt], plain: string
): string =
  # WARNING: the +128 is where things can go wrong if this proc isnt overriden properly
  result = newString(plain.len + 128)
  result[0 ..< plain.len] = plain
  let finalSize = encryptInPlace(pack, result.toOpenArray, plain.len)
  result.setLen(finalSize)

proc basicDecrypt*[T: EvpCipherSub](
    pack: sink CipherPack[T, Decrypt], cipherText: string
): string =
  result = newString(cipherText.len)
  var outLen = result.len.cint
  var finalSize = 0
  orPanick:
    pack.ctx.EVP_DecryptUpdate(
      result.cstring, outLen.addr, cipherText.cstring, cipherText.len.cint
    )
  finalSize += outLen.int
  orPanick:
    pack.ctx.EVP_DecryptFinal_ex(result[finalSize].addr, outLen.addr)
  finalSize += outLen
  result.setLen(finalSize.int)

proc genPipe(
    pack: var CipherPack,
    buffer: var openArray[byte],
    src: InputStream,
    dest: OutputStream,
    update:
      proc(a: EvpCipherContext, b: pointer, c: ptr cint, d: pointer, e: cint): cint,
    finalUpdate: proc(a: EvpCipherContext, b: pointer, c: ptr cint): cint,
    preBuf: static int,
) =
  #[
    preBuf is some space at the begining of the buffer for the cipher
    to use. Pretty dangerous becuase some algos trample the buffer. This seems to work for me though.
    A cipher block of space seems like a reasonable inner buffer, even though in-place
    updates are not always supported
  ]#
  var sz = 0.cint
  sz = src.readIntoEx(buffer.toOpenArray(preBuf, buffer.len - 1)).cint
  orPanick:
    pack.ctx.update(buffer[0].addr, sz.addr, buffer[preBuf].addr, sz)
  dest.advance(sz)
  if not src.readable:
    orPanick:
      pack.ctx.finalUpdate(buffer[sz].addr, sz.addr)
    dest.advance(sz)

proc generalCheckPipe(pack: var CipherPack, src: InputStream, dest: OutputStream) =
  #[
    WARNING: although this (pipe proc & friends) is a general proc is it meant to be
    overloaded sometimes. This assumes that 4096 is a multiple of the cipher block size
    because otherwise the input buffer may be too small, and the in-place transformation
    is undefined
  ]#
  if dest.buffers.pageSize < 32:
    raise newException(
      Defect,
      &"output page size should be at lest 32 bytes to avoid in-place buffer trampling. was {dest.buffers.pageSize}",
    )
  if dest.buffers.pageSize mod 16 != 0:
    raise newException(
      Defect,
      &"output page size should be a multiple of 16 bytes. was {dest.buffers.pageSize}",
    )

template liftInPlaceCipherPipe(cypherType: untyped, blockSize: static int): untyped =
  proc pipe*[T: CipherPack[cypherType, Encrypt]](
      pack: sink T, src: InputStream, dest: OutputStream
  ) {.gcsafe, raises: [Defect, Exception, CatchableError].} =
    # work around
    ensureRunway(dest, dest.buffers.pageSize)
    ##
    generalCheckPipe(pack, src, dest)
    {.cast(gcsafe).}:
      while src.readable:
        genPipe(
          pack,
          dest.getWritableBytes(dest.buffers.pageSize),
          src,
          dest,
          EVP_EncryptUpdate,
          EVP_EncryptFinal_ex,
          blockSize,
        )
        dest.flush()

  proc pipe*[T: CipherPack[cypherType, Decrypt]](
      pack: sink T, src: InputStream, dest: OutputStream
  ) {.gcsafe, raises: [Defect, Exception, CatchableError].} =
    # work around
    ensureRunway(dest, dest.buffers.pageSize)
    ##
    generalCheckPipe(pack, src, dest)
    {.cast(gcsafe).}:
      while src.readable:
        genPipe(
          pack,
          dest.getWritableBytes(dest.buffers.pageSize),
          src,
          dest,
          EVP_DecryptUpdate,
          EVP_DecryptFinal_ex,
          blockSize,
        )
        dest.flush()

liftInPlaceCipherPipe(EvpCipherSub, 16)

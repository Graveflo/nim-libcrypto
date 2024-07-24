import std/typetraits
import faststreams/inputs
import support
import cipher

export cipher

const AES_BLOCK_SIZE* {.importc, header: "<openssl/aes.h>".}: cint = 16

type
  AesCipher = ptr object of C_EVP_CIPHER
  Aes128Cbc* = ptr object of AesCipher
  Aes128Ecb* = ptr object of AesCipher

  AesBlockMultiple =
    concept x
        x.int mod AES_BLOCK_SIZE == 0

proc EVP_aes_128_ecb*(): EvpCipher {.importc, header: "<openssl/evp.h>".}
proc EVP_aes_128_cbc*(): EvpCipher {.importc, header: "<openssl/evp.h>".}

proc new*(
    t: typedesc[Aes128Cbc], mode: static CipherMode, key, iv: cstring
): CipherPack[Aes128Cbc, mode] =
  # 128 bit
  result.cipher = EVP_aes_128_cbc()
  newCommon(result, key, iv)

template safePointerResizable(key: auto, size: static int) {.dirty.} =
  var ks: pointer
  if key.len != size:
    var nk = key
    nk.setLen(size)
    ks = nk[0].addr
  else:
    ks = key[0].addr

template maybeSafePointerOpenArray(key: auto, size: static int) {.dirty.} =
  var ks: pointer
  when not defined(danger):
    if key.len != 16:
      var nk: array[byte, 16]
      for i in 0 ..< min(nk.len, key.len):
        nk[i] = key[i]
      ks = nk[0].addr
    else:
      ks = key[0].addr
  else:
    ks = key[0].addr

template liftBasicCipher(cipherType: untyped, keySize: static int) =
  proc new*(
      t: typedesc[cipherType], mode: static CipherMode, key: ptr [array[keySize, byte]]
  ): CipherPack[cipherType, mode] =
    result.cipher = EVP_aes_128_ecb()
    newCommon(result, key, nil)

  proc new*(
      t: typedesc[cipherType], mode: static CipherMode, key: Resizeable and MemoryView
  ): CipherPack[cipherType, mode] =
    safePointerResizable(key, keySize)
    result.cipher = EVP_aes_128_ecb()
    newCommon(result, ks, nil)

  proc new*(
      t: typedesc[cipherType], mode: static CipherMode, key: openArray[byte | char]
  ): CipherPack[cipherType, mode] =
    maybeSafePointerOpenArray(key, keySize)
    result.cipher = EVP_aes_128_ecb()
    newCommon(result, ks, nil)

  proc rinse*[T](pack: var CipherPack[T, cipherType], key: Resizeable and MemoryView) =
    safePointerResizable(key, keySize)
    orPanick:
      pack.ctx.EVP_CIPHER_CTX_cleanup()
    orPanick:
      pack.ctx.EVP_CIPHER_CTX_free()
    newCommon(pack, ks, nil)

  proc rinse*[T](pack: var CipherPack[T, cipherType], key: openArray[byte | char]) =
    maybeSafePointerOpenArray(key, keySize)
    orPanick:
      pack.ctx.EVP_CIPHER_CTX_cleanup()
    orPanick:
      pack.ctx.EVP_CIPHER_CTX_free()
    newCommon(pack, ks, nil)

  proc reuseCipher*[V: MemoryView, T, M](
      pack: CipherPack[cipherType, M],
      mode: static CipherMode,
      key: Resizeable and MemoryView,
  ): CipherPack[cipherType, mode] =
    safePointerResizable(key, 16)
    reuseCipher(pack, mode, ks, nil)

  proc reuseCipher*[V: MemoryView, T, M](
      pack: CipherPack[cipherType, M],
      mode: static CipherMode,
      key: openArray[byte | char],
  ): CipherPack[cipherType, mode] =
    maybeSafePointerOpenArray(key, keySize)
    reuseCipher(pack, mode, ks, nil)

liftBasicCipher(Aes128Ecb, 16)

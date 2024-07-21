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

proc new*(
    t: typedesc[Aes128Ecb], mode: static CipherMode, key: ptr [array[32, byte]]
): CipherPack[Aes128Ecb, mode] =
  result.cipher = EVP_aes_128_ecb()
  newCommon(result, key, nil)

proc new*(
    t: typedesc[Aes128Ecb], mode: static CipherMode, key: Resizeable and MemoryView
): CipherPack[Aes128Ecb, mode] =
  var ks: pointer
  when not defined(danger):
    if key.len != 16:
      var nk = key
      nk.setLen(16)
      ks = nk[0].addr
    else:
      ks = key[0].addr
  else:
    ks = key[0].addr
  result.cipher = EVP_aes_128_ecb()
  newCommon(result, ks, nil)

proc new*(
    t: typedesc[Aes128Ecb], mode: static CipherMode, key: openArray[byte | char]
): CipherPack[Aes128Ecb, mode] =
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
  result.cipher = EVP_aes_128_ecb()
  newCommon(result, ks, nil)

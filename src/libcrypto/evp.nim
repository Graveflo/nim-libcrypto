type
  C_ENGINE* {.importc: "ENGINE", header: "<openssl/evp.h>".} = object
  OSSL_PARAM* {.importc: "OSSL_PARAM", header: "<openssl/evp.h>".} = object
  Engine* = ptr C_ENGINE

const LibCryptoVersion* {.define.} = 31

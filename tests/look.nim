import faststreams/[inputs, outputs]
import libcrypto/[support, aes]

# for ciphers procs like `new` and `basicEncrypt` accept a variety of inputs

# the key will adjust to the correct size, unless using pointer style procs or
# `danger` is defined and using the `openArray` style procs
let key = "verysecure"
var encCipher = Aes128Ecb.new(Encrypt, key)
echo encCipher.basicEncrypt("hello world").toHex
encCipher.rinse() # loads a new context
encCipher.pipe(memoryInput("hello world"), fileOutput(stdout, pageSize = 256))

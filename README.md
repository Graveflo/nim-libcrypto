# Wrapper and high-level API for libcrypto

Currently broken - waiting on a couple of PRs into nim-lang

There already exist thin libcrypt owrappers for nim, so the idea of this one is to have a more ergonomic experience, with less of a C feel. Currently this is done with annotation-style generics, destructors and integration with [faststreams](https://github.com/status-im/nim-faststreams)

I've only wrapped AES-ECB and various SHA implementations for now because that was all I needed as my motivating reason for making this. Ciphers and message digest have a skeleton that can be added on to. Assemetric encrpytion is not something that I have looked at yet.


```nim
import faststreams/[inputs, outputs]
import libcrypto/[support, aes]

# for ciphers procs like `new` and `basicEncrypt` accept a variety of inputs

# the key will adjust to the correct size, unless using pointer style procs or
# `danger` is defined and using the `openArray` style procs
let key = "verysecure"
var encCipher = Aes128Ecb.new(Encrypt, key)
echo encCipher.basicEncrypt("hello world").toHex
encCipher.rinse()  # loads a new context
encCipher.pipe(memoryInput("hello world"), fileOutput(stdout, pageSize=256))

```


Ciphers and message digest objects have value semantics, so if you make ARC perform a copy you will get a copy of the context aswell. This can be useful
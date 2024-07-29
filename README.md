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
encCipher.rinse(key) # loads a new context

# integration with faststreams
let outp = memoryOutput(pageSize = 256)
encCipher.pipe(memoryInput("hello world"), outp)
echo outp.getOutput(string).toHex

# move semantics on cipher duplicates context if used
# after a finalizing operation
echo encCipher.basicEncrypt("hello world").toHex

# simple SHA digest
import libcrypto/sha
echo sha256.digest("foo")

# similar move semantics to ciphers
var messageDigest = newDigest(Sha512)
messageDigest.update("foo")
echo messageDigest.digest().toHex
var mdCopy = messageDigest
messageDigest.update("bar")
echo messageDigest.digest().toHex
mdCopy.update("bar")
echo mdCopy.digest().toHex
```

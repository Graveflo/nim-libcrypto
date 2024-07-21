import std/[unittest, strutils, paths, os]
import faststreams/[inputs, outputs]
import libcrypto/[support, aes]

let plaintext =
  "This is a test message. goign to make it a buit longer to try and make sure that I am past the block size. Doe this work?"
let ciphertext =
  "405F55A69E8E1AEE4854E1E67E6A9D206BFDAF4990B12BEB525234A49D1821467267A25EE0141FA009499B736F2056BB0972A3BC502E504FE8E2F5304DFB3DCF7F68D8DA37166A8DB629F37E59210FDD74BCEC78FD614E40225BC84026FEE7C02E8285F0AA01A191FCAF8152B263A0F71F622BE0F911D1122BC21C6527BE7B35"

suite "Aes Encrpytion":
  test "ECB basic encode/decode":
    let key = "asdfghjklqwertyu"
    var
      encCipher = Aes128Ecb.new(Encrypt, key)
      #decCipher = encCipher.reuseCipher(Decrypt, key)
    assert toHex(encCipher.basicEncrypt(plaintext)) == ciphertext
    #assert decCipher.basicDecrypt(parseHexStr(ciphertext)) == plaintext

  test "file stream":
    let key = "averysecurepassw"
    let secretPath = currentSourcePath().Path /../ "secret.txt".Path

    let finp = fileInput(secretPath.string)
    let outp = memoryOutput(pageSize = 4096)
    var encCipher = Aes128Ecb.new(Encrypt, key)
    encCipher.pipe(finp, outp)
    let encString = outp.getOutput(string)
    let sInp = memoryInput(encString)
    let outp2 = memoryOutput(pageSize = 4096)
    var decCipher = encCipher.reuseCipher(Decrypt, key)
    decCipher.pipe(sInp, outp2)
    assert outp2.getOutput(string) == open(secretPath.string, fmRead).readAll

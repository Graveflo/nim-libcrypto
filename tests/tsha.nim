import libcrypto/[support, sha]
import std/[unittest, strutils]

let phrase = "EVP_CIPHER_CTX_type, EVP_CIPHER_CTX_mode - EVP cipher routines"
let a224 = "6332b7b8ad985e297d28ba44a514380171ec1510138dd0095bf27525"
let a256 = "e5b99d009041ce0e13d1ee5133c75108c2e185bcb665553bf260e4a0fcf2ddf2"
let a384 =
  "a4cbfd17068d420c7d40b385e6c4ea84af596532972a526ab72fec28e7ffcab7101e65f61cc5854b48709911aa2b814f"
let a512 =
  "704d3ad1cb099d73955300fb666715bcce2a336e7876b148a7f91b14caac4f607e8d93cff1da5ef2c2477cb38957c2b7d35460f67eaa73f34f161c776ad59ba1"

suite "Sha hashes":
  test "sha digest":
    assert sha1.digest(phrase).normalize == "06c5caf19ecc67b292129715d0a024b4c4eb3742"
    assert sha224.digest(phrase).normalize == a224
    assert sha256.digest(phrase).normalize == a256
    assert sha384.digest(phrase).normalize == a384
    assert sha512.digest(phrase).normalize == a512

  test "sha 256 digest - ctx":
    var sha = newDigest(Sha256)
    sha.update(phrase[0].addr, phrase.len)
    assert sha.digest().toHex.normalize == a256

  test "sha 512 digest - ctx":
    var sha = newDigest(Sha512)
    sha.update(phrase)
    assert sha.digest().toHex.normalize == a512

  test "context realloc":
    var sha = newDigest(Sha256)
    sha.update(phrase)
    assert sha.digest().toHex.normalize == a256
    sha.realloc()
    sha.update(phrase)
    assert sha.digest().toHex.normalize == a256

  test "context duplication":
    var sha = newDigest(Sha256)
    sha.update(phrase)
    assert sha.digest().toHex.normalize == a256
    sha.update(phrase)
    assert sha.digest().toHex.normalize == sha256.digest(phrase & phrase).normalize

  test "tst lookup":
    proc reflect(p: DigestPack[Sha256]): int =
      0

    proc reflect(p: DigestPack[ShaDigest]): int =
      1

    proc reflect(p: DigestPack[MessageDigest]): int =
      2

    var sha = newDigest(Sha256)
    assert sha.reflect() == 0

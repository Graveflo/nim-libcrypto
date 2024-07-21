import std/[unittest, strutils]
import libcrypto/support

suite "Hex":
  test "test string to hex":
    let s1 = "this is a test"
    assert support.toHex(s1) == strutils.toHex(s1)
    var s2 = newString(16)
    for i in 0 ..< 8:
      s2[i] = (1.byte shl i).char
      s2[^(i + 1)] = (255.byte shl i).char
    assert support.toHex(s2) == strutils.toHex(s2)

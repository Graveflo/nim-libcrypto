import std/[strformat, typetraits]
const LIBCRYPTO_SUCCESS* = 1

type
  MemoryView* =
    concept x
        x[0].addr
  RunSafeMemView* =
    concept x
        x[0].addr
        len(x) is Natural
  Resizeable* =
    concept x
        x.setLen(1)
  OpenArrayLike* =
    concept x
        toOpenArray(x, 0, len(x)) is openArray
  BoundedIndexable =
    concept x, y
        x[0]
        x[0] = y
        x[0 .. 0] = y[0 .. 0]
        len(x) is Natural
        BoundedIndexable(x[0 .. 0])

proc contCopy*(dest, src: OpenArrayLike) =
  dest[0 ..< len(src)] = src[0 ..< len(src)]

const HexChars = "0123456789ABCDEF"
proc toHex*[T](v: ptr UncheckedArray[T], len: int): string =
  let blen = sizeof(T) * len
  let bref = cast[ptr UncheckedArray[byte]](v)
  result = newString(blen * 2)
  for i in 0 ..< blen:
    var c = bref[i]
    result[(i * 2) + 1] = HexChars[c and 0x0F.byte]
    c = c shr 4
    result[i * 2] = HexChars[c]

proc toHex*[T](v: openArray[T]): string =
  toHex(cast[ptr UncheckedArray[T]](v.addr), v.len)

template toOpenArray*(s: OpenArrayLike): untyped =
  toOpenArray(s, 0, s.len - 1)

proc `$`*(p: ref | ptr): string =
  mixin `$`
  # perilous to cyclical datastructures in case you didnt notice
  var ts = $p.typeOf.pointerBase()
  let desc = when (p.typeOf is ref): "Ref" else: "Pointer"
  let my_hex = toHex(cast[int](p))
  result = fmt"{desc}[{ts}]"
  if p == nil:
    result &= ": nil"
  else:
    result &= fmt" @ {my_hex}: {$p[]}"

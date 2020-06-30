module base64
export NoPadding, StdPadding
export CorruptInput, InvalidAlphabet, InvalidPadCharacter
export Encoding, NewEncoding, WithPadding, Strict
export StdEncoding, URLEncoding, RawURLEncoding, RawStdEncoding
export EncodedLen, Encode!, EncodeToString
export DecodedLen, Decode!, DecodeString

const StdPadding = 0x3d
const NoPadding = 0x00

const std_codec = [UInt8(x) for x in ['A':'Z'; 'a':'z'; '0':'9'; '+'; '/']]
const url_codec = [UInt8(x) for x in ['A':'Z'; 'a':'z'; '0':'9'; '-'; '_']]


struct CorruptInput <: Exception end
struct InvalidAlphabet <: Exception end
struct InvalidPadCharacter <: Exception end

struct Encoding
	encode::Array{UInt8, 1}
	decodeMap::Array{UInt8, 1}
	padChar::UInt8
  strict::Bool

  Encoding(encode::Array{UInt8, 1}, decodeMap::Array{UInt8, 1}, padChar::UInt8, strict::Bool) = new(encode, decodeMap, padChar, strict)
  Encoding(;encode::Array{UInt8, 1}, decodeMap::Array{UInt8, 1} = fill(0xff, 256), padChar::UInt8 = StdPadding, strict::Bool=false) = new(encode, decodeMap, padChar, strict)
end

@inline function assemble_64(n1::UInt8, n2::UInt8, n3::UInt8, n4::UInt8, n5::UInt8, n6::UInt8, n7::UInt8, n8::UInt8) :: Union{Nothing, UInt64}
  n1|n2|n3|n4|n5|n6|n7|n8 != 0xff && return UInt64(n1)<<58 | UInt64(n2)<<52 | UInt64(n3)<<46 | UInt64(n4)<<40 | UInt64(n5)<<34 | UInt64(n6)<<28 | UInt64(n7)<<22 | UInt64(n8)<<16
end

@inline function assemble_32(n1::UInt8, n2::UInt8, n3::UInt8, n4::UInt8) :: Union{Nothing, UInt32}
  n1|n2|n3|n4 != 0xff && return UInt32(n1)<<26 | UInt32(n2)<<20 | UInt32(n3)<<14 | UInt32(n4)<<8
end

@inline function put_64!(dst::AbstractArray{UInt8, 1}, val::UInt64) :: Nothing
  length(dst) < 8 && throw(BoundsError("destinary array out of bounds"))
  dst[1] = val>>56 & 0xff
  dst[2] = val>>48 & 0xff
  dst[3] = val>>40 & 0xff
  dst[4] = val>>32 & 0xff
  dst[5] = val>>24 & 0xff
  dst[6] = val>>16 & 0xff
  dst[7] = val>>8 & 0xff
	dst[8] = val & 0xff
	nothing
end

@inline function put_32!(dst::AbstractArray{UInt8, 1}, val::UInt32) :: Nothing
  length(dst) < 4 && throw(BoundsError("destinary array out of bounds"))
  dst[1] = val>>24 & 0xff
  dst[2] = val>>16 & 0xff
  dst[3] = val>>8 & 0xff
	dst[4] = val & 0xff
	nothing
end

function NewEncoding(alphabet::Array{UInt8, 1}) :: Encoding
  length(alphabet) != 64 && throw(InvalidAlphabet())
  check = in(alphabet)
  (check(0x0d) || check(0x0a)) && throw(InvalidAlphabet())
  encoder = Encoding(encode=alphabet)
  for i in 1:64
    @inbounds encoder.decodeMap[alphabet[i]] = i & 0xff - 1
  end
  return encoder
end
NewEncoding(alphabet::String) = NewEncoding(Array{UInt8, 1}(alphabet))

function WithPadding(enc::Encoding, pad_char::UInt8) :: Encoding
  (pad_char == 0x0d || pad_char == 0x0a || pad_char > 0x3d || in(pad_char, enc.encode)) && throw(InvalidPadCharacter())
  Encoding(enc.encode, enc.decodeMap, pad_char, enc.strict)
end
WithPadding(enc::Encoding, pad_char::Char) = WithPadding(enc, UInt8(pad_char))

function Strict(enc::Encoding) :: Encoding
  Encoding(enc.encode, enc.decodeMap, enc.padChar, true)
end

const StdEncoding = NewEncoding(std_codec)
const URLEncoding = NewEncoding(url_codec)

const RawStdEncoding = WithPadding(StdEncoding, NoPadding)
const RawURLEncoding = WithPadding(URLEncoding, NoPadding)

@inline function EncodedLen(enc::Encoding, n::Int) :: Int
  if enc.padChar == NoPadding
    return convert(Int, floor((n*8 + 5) / 6))
  end
  convert(Int, floor((n+2) / 3) * 4)
end

function Encode!(enc::Encoding, dst::Array{UInt8, 1}, src::Array{UInt8, 1}) :: Nothing
  isempty(src) && return nothing
  di, si, n = 1, 1, convert(Int, floor(length(src) / 3) * 3)
  while si <= n
    v = UInt(src[si+0])<<16 | UInt(src[si+1])<<8 | UInt(src[si+2])
    @inbounds dst[di+0] = enc.encode[v>>18&0x3f + 1]
    @inbounds dst[di+1] = enc.encode[v>>12&0x3f + 1]
    @inbounds dst[di+2] = enc.encode[v>>6&0x3f + 1]
    @inbounds dst[di+3] = enc.encode[v&0x3f + 1]

    si += 3
    di += 4
  end

  rem = length(src) - si + 1
  rem == 0 && return nothing

  v = UInt(src[si+0]) << 16
  rem == 2 && (v |= UInt(src[si+1]) << 8)

  @inbounds dst[di+0] = enc.encode[v>>18&0x3f + 1]
  @inbounds dst[di+1] = enc.encode[v>>12&0x3f + 1]
  
  if rem == 2
    @inbounds dst[di+2] = enc.encode[v>>6&0x3f]
		if enc.padChar != NoPadding
			@inbounds dst[di+3] = enc.padChar
    end
  elseif rem == 1
    if enc.padChar != NoPadding
      @inbounds dst[di+2] = enc.padChar
      @inbounds dst[di+3] = enc.padChar
    end
  end
  nothing
end

@inline function EncodeToString(enc::Encoding, src::Array{UInt8, 1}) :: String
  buf = fill(enc.padChar, EncodedLen(enc, length(src)))
  Encode!(enc, buf, src)
  String(buf)
end
EncodeToString(enc::Encoding, src::String) = EncodeToString(enc, Array{UInt8, 1}(src))


@inline function DecodedLen(enc::Encoding, n::Int) :: Int
  if enc.padChar == NoPadding
    return convert(Int, floor(n * 6 / 8))
  end
  convert(Int, floor(n / 4 * 3))
end

function decode_quantum!(enc::Encoding, dst::AbstractArray{UInt8, 1}, src::Array{UInt8, 1}, si::Int) :: Tuple{Int, Int}
	dbuf = zeros(4)
	dlen = 4

  j = 1
  while j < length(dbuf)
    if length(src) == si
      if j == 1
        return si, 0
      elseif j == 2 || enc.padChar != NoPadding
        throw(CorruptInput())
      end
      dlen = j - 1
      break
    end
    i = src[si + 1]
    si += 1
    o = enc.decodeMap[i]
    if o != 0xff
      dbuf[j] = o
      j += 1
      continue
    end
    if i == 0x0d || i == 0x0a
      j -= 1
      continue
    end
    if i != enc.padChar
      throw(CorruptInput())
    end
    if j == 1 || j == 2
      throw(CorruptInput())
    elseif j == 3
      while si < length(src) && (src[si+1] == 0x0d || src[si+1] == 0x0a)
        si += 1
      end
      (si == length(src) || src[si+1] != enc.padChar) && throw(CorruptInput())
      si += 1
    end

    while si < length(src) && (src[si+1] == 0x0d || src[si+1] == 0x0a)
      si += 1
    end

    (si < length(src)) && throw(CorruptInput())
    dlen = j - 1
    break
  end

  v = UInt(dbuf[1])<<18 | UInt(dbuf[2])<<12 | UInt(dbuf[3])<<6 | UInt(dbuf[4])
  dbuf[3], dbuf[2], dbuf[1] = v>>0 & 0xff, v>>8 & 0xff, v>>16 & 0xff 
  if dlen == 4
    @inbounds dst[3] = dbuf[3]
    dbuf[3] = 0
  end
  if dlen == 4 || dlen == 3
    @inbounds dst[2] = dbuf[2]
    if enc.strict && dbuf[3] != 0
      throw(CorruptInput())
    end
    dbuf[2] = 0
  end
  if dlen == 4 || dlen == 3 || dlen == 2
    @inbounds dst[1] = dbuf[1]
    if enc.strict && (dbuf[2] != 0 || dbuf[3] != 0)
      throw(CorruptInput())
    end
  end
  return si, dlen-1
end

function Decode!(enc::Encoding, dst::Array{UInt8, 1}, src::Array{UInt8, 1}) :: Int
  isempty(src) && return nothing
  si, n = 0, 0
  @show src
  while length(src) - si >= 8 && length(dst) - n >= 8
    dn = assemble_64(
      enc.decodeMap[src[si+1]],
			enc.decodeMap[src[si+2]],
			enc.decodeMap[src[si+3]],
			enc.decodeMap[src[si+4]],
			enc.decodeMap[src[si+5]],
			enc.decodeMap[src[si+6]],
			enc.decodeMap[src[si+7]],
			enc.decodeMap[src[si+8]],
    )
    if !isnothing(dn)
      put_64!(view(dst, n+1:length(dst)), dn)
      n += 6
      si += 8
    else
      si, ni = decode_quantum!(enc, view(dst, n+1:length(dst)), src, si)
      @show si
      n += ni
    end
  end

  while length(src)-si >= 4 && length(dst)-n >= 4
    dn = assemble_32(
      enc.decodeMap[src[si+1]],
			enc.decodeMap[src[si+2]],
			enc.decodeMap[src[si+3]],
			enc.decodeMap[src[si+4]],
    )
    if !isnothing(dn)
      put_32!(view(dst, n+1:length(dst)), dn)
      n += 3
      si += 4
    else
      si, ni = decode_quantum!(enc, view(dst, n+1:length(dst)), src, si)
      n += ni
    end
  end

  if si < length(src)
    si, ni = decode_quantum!(enc, view(dst, n+1:length(dst)), src, si)
    n += ni
  end
  return n
end

@inline function DecodeString(enc::Encoding, src::Array{UInt8, 1}) :: String
  buf = fill(enc.padChar, DecodedLen(enc, length(src)))
  n = Decode!(enc, buf, src)
  String(buf[1:n])
end
DecodeString(enc::Encoding, src::String) = DecodeString(enc, Array{UInt8, 1}(src))

end
import Base64

const encode_codec = [UInt8(x) for x in ['.'; '/'; 'A':'Z'; 'a':'z'; '0':'9']]
Base64.encode(x::UInt8) = @inbounds return codec[(x & 0x3f) + 1]

const BASE64_CODE_END = 0x40
const BASE64_CODE_PAD = 0x41
const BASE64_CODE_IGN = 0x42
const decode_codec = fill(BASE64_CODE_IGN, 256)
for (i, c) in enumerate(encode_codec)
    decode_codec[Int(c)+1] = UInt8((i - 1) & 0xff)
end
decode_codec[Int(UInt8('='))+1] = BASE64_CODE_PAD
Base64.decode(x::UInt8) = @inbounds return decode_codec[x + 1]

bcrypt_b64_encode(s::String) = begin
	dst = Base64.base64encode(s)
	rstrip(dst, '=')
end

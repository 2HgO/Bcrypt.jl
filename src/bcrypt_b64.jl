module bcrypt_b64

export bcrypt_b64_decode, bcrypt_b64_encode

import ..base64

const codec = [UInt8(x) for x in ['.'; '/'; 'A':'Z'; 'a':'z'; '0':'9']]

const BcryptEncoding = base64.NewEncoding(codec)

@inline function bcrypt_b64_encode(src::Array{UInt8, 1})
	n = base64.EncodedLen(BcryptEncoding, length(src))
	dst = zeros(UInt8, n)
	base64.Encode!(BcryptEncoding, dst, src)
	while dst[n] == 0x3d
		n -= 1
	end
	return dst[1:n]
end

@inline function bcrypt_b64_decode(src::Array{UInt8, 1}) :: Array{UInt8, 1}
	j = 4-(length(src) % 4)
	for _ = 0:j-1
		push!(src, 0x3d)
	end
	n = base64.DecodedLen(BcryptEncoding, length(src))
	dst = zeros(UInt8, n)
	i = base64.Decode!(BcryptEncoding, dst, src)
	return dst[1:i]
end

end
module Bcrypt

include("base64.jl")
include("bcrypt_b64.jl"); using .bcrypt_b64

import Blowfish
import Random
import Printf: @sprintf

const MinCost = 4
const MaxCost = 31
const DefaultCost = 10

const majorVersion       = 0x32
const minorVersion       = 0x61
const maxSaltSize        = 16
const maxCryptedHashSize = 23
const encodedSaltSize    = 22
const encodedHashSize    = 31
const minHashSize        = 59

const magicCipherData = (
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
)::NTuple{24, UInt8}

struct InvalidCost <: Exception end
struct HashTooShort <: Exception end

struct hashed
	hash::Array{UInt8, 1}
	salt::Array{UInt8, 1}
	cost::Int
	major::UInt8
	minor::UInt8
end

@inline function GenerateFromPassword(password::Array{UInt8, 1}, cost::Int = DefaultCost) :: Array{UInt8, 1}
	hash(newFromPassword(password, cost))
end
GenerateFromPassword(password::String, cost::Int = DefaultCost) = GenerateFromPassword(Array{UInt8, 1}(password), cost) 

@inline function CompareHashAndPassword(hashedPassword::Array{UInt8, 1}, password::Array{UInt8, 1}) :: Bool
	# try
		p = newFromHash(hashedPassword)
		other = bcrypt(password, p.cost, p.salt)
		ot = hashed(other, p.salt, p.cost, p.major, p.minor)
		c = constantTimeCompare(hash(hashed(other, p.salt, p.cost, p.major, p.minor)), hash(p))
		@show c
		c == 1
	# catch
	# end
	# return false
end
CompareHashAndPassword(hashedPassword::String, password::String) = CompareHashAndPassword(Array{UInt8, 1}(hashedPassword), Array{UInt8, 1}(password))

@inline function constantTimeCompare(a::Array{UInt8, 1}, b::Array{UInt8, 1}) :: Int
	length(a) != length(b) && return 0
	v = UInt8(0)
	for i = 1:length(a)
		v |= a[i] ⊻ b[i]
	end
	constantTimeByteEq(v, UInt8(0))
end

constantTimeByteEq(a::UInt8, b::UInt8) = convert(Int, UInt32(a^b))

function Cost(hashedPassword::Array{UInt8, 1}) :: Int
	newFromHash(hashedPassword).cost
end

function newFromPassword(password::Array{UInt8, 1}, cost::Int) :: hashed
	if cost < MinCost
		cost = DefaultCost
	end
	(cost > MaxCost || cost < MinCost) && throw(InvalidCost())
	rng = Random.RandomDevice()
	unencodedSalt = Random.rand!(rng, zeros(UInt8, maxSaltSize))
	salt = bcrypt_b64_encode(unencodedSalt)
	hash = bcrypt(password, cost, salt)
	hashed(hash, salt, cost, majorVersion, minorVersion)
end

function newFromHash(hashedSecret::Array{UInt8, 1}) :: hashed
	length(hashedSecret) < minHashSize && throw(HashTooShort())
	n, minor, major = decodeVersion(hashedSecret)
	hashedSecret = hashedSecret[n+1:end]
	n, cost = decodeCost(hashedSecret)
	hashedSecret = hashedSecret[n+1:end]
	salt = copyto!(zeros(UInt8, encodedSaltSize), hashedSecret[1:encodedSaltSize])
	hashedSecret = hashedSecret[encodedSaltSize+1:end]
	hsh = copyto!(zeros(UInt8, length(hashedSecret)), hashedSecret)
	hashed(hsh, salt, cost, major, minor)
end

function bcrypt(password::Array{UInt8, 1}, cost::Int, salt::Array{UInt8, 1}) :: Array{UInt8, 1}
	cipherData = collect(magicCipherData)
	c = expensiveBlowfishSetup(password, UInt32(cost), salt)
	for i = 1:8:24
		for j = 1:64
			Blowfish.Encrypt!(c, view(cipherData, i:i+7), cipherData[i:i+7])
		end
	end
	bcrypt_b64_encode(cipherData[1:maxCryptedHashSize])
end
Blowfish.Encrypt!(c::Blowfish.Cipher, a::AbstractArray{UInt8, 1}, b::AbstractArray{UInt8, 1}) = begin
	d = Array{UInt8, 1}(a)
	Blowfish.Encrypt!(c, d, b)
	copyto!(a, d)
end


function expensiveBlowfishSetup(key::Array{UInt8, 1}, cost::UInt32, salt::Array{UInt8, 1}) :: Blowfish.Cipher
	csalt = bcrypt_b64_decode(salt)
	ckey = push!(key, 0x00)
	c = Blowfish.NewSaltedCipher(ckey, csalt)
	rounds = UInt64(1 << cost)
	for i = 1:rounds
		Blowfish.ExpandKey!(ckey, c)
		Blowfish.ExpandKey!(csalt, c)
	end
	return c
end

function Hash(obj::hashed)
	arr = zeros(UInt8, 60)
	arr[1] = 0x24
	arr[2] = obj.major
	n = 3
	if obj.minor != 0
		arr[3] = obj.minor
		n = 4
	end
	arr[n] = 0x24
	n += 1
	copyto!(view(arr, n:60), Array{UInt8, 1}(@sprintf "%02d" obj.cost))
	n += 2
	arr[n] = 0x24
	n += 1
	copyto!(view(arr, n:60), obj.salt)
	n += encodedSaltSize
	copyto!(view(arr, n:60), obj.hash)
	n += encodedHashSize
	return arr[1:n-1]
end
Base.hash(p::hashed) = Hash(p)

function decodeVersion(src::Array{UInt8, 1}) :: Tuple{Int, UInt8, UInt8}
	src[1] != 0x24 && throw("")
	src[2] > majorVersion && throw("")
	major = src[2]
	n, minor = 3, UInt8(0)
	if src[3] != 0x24
		minor = src[3]
		n += 1
	end
	return n, minor, major
end

function decodeCost(src::Array{UInt8, 1}) :: Tuple{Int, Int}
	cost = parse(Int, String(src[1:2]))
	(cost > MaxCost || cost < MinCost) && throw(InvalidCost())
	return 3, cost
end

end # module

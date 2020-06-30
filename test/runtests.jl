import Bcrypt

import Printf: @sprintf
using Test

@testset "test bcrypt is easy" begin
	pass = Array{UInt8,1}("mypassword")
	hashPass = Bcrypt.GenerateFromPassword(pass, 0)
	@test Bcrypt.CompareHashAndPassword(hashPass, pass)
	
	notPass = Array{UInt8,1}("notthepass")
	@test Bcrypt.CompareHashAndPassword(hashPass, notPass) == false
end

@testset "test bcrypt is correct" begin
	pass = Array{UInt8, 1}("allmine")
	salt = Array{UInt8, 1}("XajjQvNhvvRt5GSeFk1xFe")
	expect = Array{UInt8, 1}("\$2a\$10\$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga")

	hsh = Bcrypt.bcrypt(pass[1:end], 10, salt[1:end])
	@test endswith(String(expect[1:end]), String(hsh[1:end]))

	h = Bcrypt.newFromHash(expect)
	@test expect == hash(h)
end

@testset "test very short passwords" begin
	key = UInt8[0x6b]
	salt = Array{UInt8, 1}("XajjQvNhvvRt5GSeFk1xFe")
	Bcrypt.bcrypt(key, 10, salt)
	@test true
end

@testset "test too long passwords work" begin
	salt = Array{UInt8, 1}("XajjQvNhvvRt5GSeFk1xFe")
	longPass = Array{UInt8, 1}("012345678901234567890123456789012345678901234567890123456")
	longExpect = Array{UInt8, 1}("\$2a\$10\$XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C")
	hsh = Bcrypt.bcrypt(longPass[1:end], 10, salt[1:end])
	@test endswith(String(longExpect[1:end]), String(hsh[1:end]))
end

struct invalidHashTest
	err::Type{<:Exception}
	hsh::Array{UInt8, 1}
end

const invalidTests = invalidHashTest[
	invalidHashTest(Bcrypt.HashTooShort, Array{UInt8,1}("\$2a\$10\$fooo")),
	invalidHashTest(Bcrypt.HashTooShort, Array{UInt8,1}("\$2a")),
	invalidHashTest(Bcrypt.HashVersionTooNew, Array{UInt8,1}("\$3a\$10\$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")),
	invalidHashTest(Bcrypt.InvalidHashPrefix, Array{UInt8,1}("%2a\$10\$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")),
	invalidHashTest(Bcrypt.InvalidCost, Array{UInt8,1}("\$2a\$32\$sssssssssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")),
]

@testset "test invalid hash exceptions" begin
	for case in invalidTests
		try
			Bcrypt.newFromHash(case.hsh)
		catch ex
			@test isa(ex, case.err)
		end
		try
			Bcrypt.CompareHashAndPassword(case.hsh, Array{UInt8,1}("rando"))
		catch ex
			@test isa(ex, case.err)
		end
	end
end

@testset "test unpadded b64 encoding" begin
	original = UInt8[101, 201, 101, 75, 19, 227, 199, 20, 239, 236, 133, 32, 30, 109, 243, 30]
	encodedOriginal = Array{UInt8, 1}("XajjQvNhvvRt5GSeFk1xFe")

	encoded = Bcrypt.bcrypt_b64_encode(original[1:end])
	@test encoded == encodedOriginal

	decoded = Bcrypt.bcrypt_b64_decode(encodedOriginal[1:end])
	@test decoded == original
end

@testset "test cost" begin
	suffix = "XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C"
	for version in ["2a", "2"]
		for cost in [4, 10]
			s = @sprintf "\$%s\$%02d\$%s" version cost suffix
			h = Array{UInt8, 1}(s)
			actual = Bcrypt.Cost(h)
			@test actual == cost
		end
	end
	try
		Bcrypt.Cost(Array{UInt8, 1}("\$a\$a\$$suffix"))
	catch ex
		@test isa(ex, Bcrypt.HashTooShort)
	end
end

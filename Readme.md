# Bcrypt.jl

Bcrypt.jl is an implementation [Provos and Mazières's bcrypt adaptive hashing algorithm](http://www.usenix.org/event/usenix99/provos/provos.pdf).

This implementation was loosely transcribed from the [Go](https://golang.org)(golang) implementation of the algorithm.
See [crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt).

## Installation
---
From a julia session, run:
```julia-repl
julia> using Pkg
julia> Pkg.add("Bcrypt")
```

## License
---
The source code for the package `Bcrypt.jl` is licensed under the MIT License.
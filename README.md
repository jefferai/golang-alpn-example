# golang-alpn-example

This is an example of using the NPN/ALPN support in Go's TLS and HTTP libraries
to allow a single TLS listener and `http.Server` to handle both HTTP/2 and
arbitrary protocol clients on the same port. See the code for more detailed
comments.

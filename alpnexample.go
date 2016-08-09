package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	uuid "github.com/hashicorp/go-uuid"

	"golang.org/x/net/http2"
)

// This program demonstrates using ALPN with TLS to handle both HTTP/2 traffic
// and an arbitrary protocol called "foo". Although this method of multiplexing
// requires multiple TCP connections, the number is few (since HTTP/2 reuses
// connections and multiplexes and yamux can be layered on top of a given
// net.Conn), and the same port can be used because the protocol switch happens
// during TLS negotiation.
//
// The sleep times are distinct between the foo and HTTP/2 clients to make it
// clear that they are running concurrently/async.

var (
	wg          = &sync.WaitGroup{}
	certBytes   []byte
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	shutdownCh  = make(chan struct{})
	h2TLSConfig *tls.Config
	certPool    = x509.NewCertPool()
)

// runServer runs a TLS connection that indicates support for HTTP/2 and for
// arbitrary protocol "foo" negotiated via TLS ALPN. The server contains a
// mapping of this protocol name to handleFoo. For demonstrating HTTP request
// handling, it implements a route that simply returns "gotcha" back to the
// client.
func runServer() {
	defer wg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("/h2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("handling /h2 for client\n")
		w.Write([]byte("gotcha"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:7999")
	if err != nil {
		fmt.Printf("error starting listener: %v\n", err)
		os.Exit(1)
	}
	tlsLn := tls.NewListener(ln, h2TLSConfig)

	server := &http.Server{
		Addr:    "127.0.0.1:7999",
		Handler: mux,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			"foo": handleFoo,
		},
	}

	http2.ConfigureServer(server, nil)

	go func() {
		err = server.Serve(tlsLn)
		fmt.Printf("server returned: %v\n", err)
	}()

	//fmt.Printf("server nextprotos: %#v\n", server.TLSNextProto)

	select {
	case <-shutdownCh:
		return
	}
}

// runHTTP2Client uses the same TLS configuration, including next protos, as
// the server; however, since its transport will only be configured for HTTP/2,
// plus HTTP/1.1 in order to run the protocol upgrade, it will always match the
// HTTP/2 side of the server. The client simply spins in a loop making gets to
// the server's "/h2" endpoint.
func runHTTP2Client() {
	defer wg.Done()

	var resp *http.Response
	var err error
	buf := bytes.NewBuffer(nil)

	tp := &http.Transport{
		TLSClientConfig: h2TLSConfig,
	}
	err = http2.ConfigureTransport(tp)
	if err != nil {
		fmt.Printf("error configuring transport: %v\n", err)
		os.Exit(1)
	}
	client := &http.Client{
		Transport: tp,
	}

	for {
		time.Sleep(1 * time.Second)
		select {
		case <-shutdownCh:
			return
		default:
			buf.Reset()
			req, err := http.NewRequest("GET", "https://localhost:7999/h2", nil)
			if err != nil {
				fmt.Printf("error during request creation: %v\n", err)
				continue
			}
			fmt.Printf("h2 client sending request\n")
			resp, err = client.Do(req)
			if err != nil {
				fmt.Printf("error during client get: %v\n", err)
				continue
			}
			_, err = buf.ReadFrom(resp.Body)
			if err != nil {
				fmt.Printf("error during body read: %v\n", err)
				continue
			}
			fmt.Printf("h2 client got: %v\n", buf.String())
			resp.Body.Close()
		}
	}
}

// handleFoo is started by the selection of "foo" as the protocol, which the
// foo client advertises as its only supported protocol. The function is given
// a raw tls.Conn, over which we can do anything we like -- this is a simple
// echo server with read/write deadlines.
func handleFoo(server *http.Server, conn *tls.Conn, handler http.Handler) {
	wg.Add(1)
	defer wg.Done()

	//fmt.Printf("handle foo started, server:\n%#v\nconn:\n%#v\nhandler:\n%#v\n", *server, *conn, handler)
	fmt.Printf("handle foo started\n")

	rdr := bufio.NewReader(conn)
	wtr := bufio.NewWriter(conn)
	for {
		select {
		case <-shutdownCh:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := rdr.ReadString('\n')
			if err != nil {
				fmt.Printf("error during foo server reading: %v\n", err)
				continue
			}

			fmt.Printf("foo server got %s\n", line)

			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = wtr.WriteString(line)
			if err != nil {
				fmt.Printf("error during foo client writing: %v\n", err)
			}
			err = wtr.Flush()
			if err != nil {
				fmt.Printf("error during foo client write flush: %v\n", err)
				continue
			}
			fmt.Printf("foo server wrote %s\n", line)
		}
	}
}

// runFooClient creates a TLS connection with only a single acceptable
// NextProto, forcing selection of the "foo" protocol (this is why it does not
// share the same tls.Config as elsewhere). Once connected, it performs a
// simple read/write echo with the server.
func runFooClient() {
	defer wg.Done()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{certBytes},
				PrivateKey:  key,
			},
		},
		RootCAs: certPool,
		NextProtos: []string{
			"foo",
		},
	}

	conn, err := tls.Dial("tcp", "localhost:7999", tlsConfig)
	if err != nil {
		fmt.Printf("error dialing foo client: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("foo client connected\n")

	rdr := bufio.NewReader(conn)
	wtr := bufio.NewWriter(conn)

	for {
		time.Sleep(1300 * time.Millisecond)
		select {
		case <-shutdownCh:
			return
		default:
			uuid, _ := uuid.GenerateUUID()
			id := uuid + "\n"
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = wtr.WriteString(id)
			if err != nil {
				fmt.Printf("error during foo client writing: %v\n", err)
				continue
			}
			err = wtr.Flush()
			if err != nil {
				fmt.Printf("error during foo client write flush: %v\n", err)
				continue
			}
			fmt.Printf("foo client wrote %s\n", id)

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := rdr.ReadString('\n')
			if err != nil {
				fmt.Printf("error during foo client reading: %v\n", err)
				continue
			}
			fmt.Printf("foo client read: %v\n", line)
		}
	}
}

// main generates a shared, self-signed certificate, sets up the mostly-shared
// TLS configuration, adds Ctrl-C handling for easy exit, and then starts the
// various other functions running, waiting for them to finish after a Ctrl-C.
func main() {
	var err error
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("error generating key: %v\n", err)
		os.Exit(1)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-1 * time.Second),
		NotAfter:              time.Now().Add(1 * time.Hour),
		BasicConstraintsValid: true,
		IsCA: true,
	}

	certBytes, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		fmt.Printf("error generating self-signed cert: %v\n", err)
		os.Exit(1)
	}

	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Printf("error parsing generated certificate: %v\n", err)
		os.Exit(1)
	}

	certPool.AddCert(cert)

	h2TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{certBytes},
				PrivateKey:  key,
			},
		},
		RootCAs:    certPool,
		ServerName: "localhost",
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
		NextProtos: []string{
			"h2",
			"foo",
		},
	}

	sighupCh := make(chan os.Signal, 4)
	signal.Notify(sighupCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sighupCh
		close(shutdownCh)
	}()

	wg.Add(3)
	go runServer()
	// Give the server a moment to run
	time.Sleep(1 * time.Second)
	go runHTTP2Client()
	go runFooClient()

	wg.Wait()
}

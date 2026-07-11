package pipe

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// halfCloseConn wraps one end of net.Pipe with a CloseWrite that only
// signals EOF to the peer's reads, like a real TCP half-close.
type halfCloseConn struct {
	net.Conn
	wroteEOF chan struct{} // closed by CloseWrite
}

func (c *halfCloseConn) CloseWrite() error {
	close(c.wroteEOF)
	return nil
}

func TestRunBidirectionalWithHalfClose(t *testing.T) {
	local, remote := net.Pipe()
	conn := &halfCloseConn{Conn: local, wroteEOF: make(chan struct{})}
	in := strings.NewReader("to-server")
	var out bytes.Buffer

	// Fake peer: read what stdin sent, observe the half-close, answer,
	// then close the connection.
	go func() {
		buf := make([]byte, len("to-server"))
		if _, err := io.ReadFull(remote, buf); err != nil {
			t.Errorf("peer read: %v", err)
		}
		if string(buf) != "to-server" {
			t.Errorf("peer got %q", buf)
		}
		<-conn.wroteEOF // stdin EOF must arrive as CloseWrite
		remote.Write([]byte("to-client"))
		remote.Close()
	}()

	if err := Run(conn, in, &out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := out.String(); got != "to-client" {
		t.Errorf("stdout got %q, want %q", got, "to-client")
	}
}

// Without CloseWrite support, stdin EOF must fall back to closing the
// whole connection, and that self-inflicted close is not an error.
func TestRunCloseWriteFallback(t *testing.T) {
	local, remote := net.Pipe()
	go io.Copy(io.Discard, remote)

	done := make(chan error, 1)
	go func() { done <- Run(local, strings.NewReader("bye"), io.Discard) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stdin EOF")
	}
	// The peer must see the connection closed.
	remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := remote.Read(make([]byte, 1)); err != io.EOF && err != io.ErrClosedPipe {
		t.Errorf("peer read after close: %v", err)
	}
}

// When the peer closes first, Run must return even though stdin stays open.
func TestRunPeerCloseFirst(t *testing.T) {
	local, remote := net.Pipe()
	stdinR, _ := io.Pipe() // never delivers EOF
	var out bytes.Buffer

	go func() {
		remote.Write([]byte("server-banner"))
		remote.Close()
	}()

	done := make(chan error, 1)
	go func() { done <- Run(local, stdinR, &out) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after peer close")
	}
	if got := out.String(); got != "server-banner" {
		t.Errorf("stdout got %q, want %q", got, "server-banner")
	}
}

// Package pipe bridges an SSH ProxyCommand's stdin/stdout to a net.Conn.
package pipe

import (
	"errors"
	"io"
	"net"
)

type closeWriter interface {
	CloseWrite() error
}

// Run copies in→conn and conn→out until the connection is over.
//
// Half-close handling: when in reaches EOF the write side of conn is closed
// (CloseWrite if available) so the peer sees EOF while data it is still
// sending keeps flowing. Run returns when conn reaches EOF, i.e. when the
// peer has closed its side.
func Run(conn net.Conn, in io.Reader, out io.Writer) error {
	go func() {
		io.Copy(conn, in)
		if cw, ok := conn.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			conn.Close()
		}
	}()

	_, err := io.Copy(out, conn)
	conn.Close()
	// The conn.Close() fallback above makes this copy fail with a
	// "closed" error; that is a normal shutdown, not a failure.
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return err
	}
	return nil
}

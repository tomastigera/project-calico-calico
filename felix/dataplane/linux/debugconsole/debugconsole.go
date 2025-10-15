// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package debugconsole

import (
	"fmt"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	SockAddrFolder   = "/var/run/calico/felix"
	SockAddrFileName = "debug"
	SockAddr         = SockAddrFolder + "/" + SockAddrFileName
)

type DebugConsole interface {
	Start()
}

type PacketProcessorDebugRestarter interface {
	DebugKillCurrentNfqueueConnection() error
}

type debugConsole struct {
	connChan                 chan net.Conn
	packetProcessorRestarter PacketProcessorDebugRestarter
}

func New(packetProcessorRestarter PacketProcessorDebugRestarter) DebugConsole {
	if err := os.MkdirAll(SockAddrFolder, os.ModeDir); err != nil {
		log.WithError(err).Fatal("failed to create socket path")
	}

	return &debugConsole{
		packetProcessorRestarter: packetProcessorRestarter,
		connChan:                 make(chan net.Conn),
	}
}

// Start opens a unix socket (at the location of SockAddr) and listens for commands over that socket.
// Commands can be sent to the debug console using netcat as follows:
//
//	echo <command> <arguments> | nc -U /var/run/calico/felix/debug
//
// If the command was executed successfully "success" will be printed out, otherwise "fail: <error-message>" will be
// printed.
//
// Available commands:
//
// close-nfqueue-conn: close the current connection with nfqueue. This is useful to test the current behaviour with
// unexpected errors closing down the connection (either from the dataplane or the user program).
func (console debugConsole) Start() {
	if err := os.RemoveAll(SockAddr); err != nil {
		log.WithError(err).Fatal("failed to remove socket")
	}

	go console.loopAcceptingConnections()
}

func (console *debugConsole) loopAcceptingConnections() {
	l, err := net.Listen("unix", SockAddr)
	if err != nil {
		log.WithError(err).Error("failed to listen on socket")
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.WithError(err).Error("failed to accept connections")
			return
		}

		go console.handleConnection(conn)
	}
}

func (console *debugConsole) handleConnection(c net.Conn) {
	var bytes [2048]byte

	i, err := c.Read(bytes[:])
	if err != nil {
		log.WithError(err).Error("failed to read request")
		return
	}

	args := strings.Split(string(bytes[0:i-1]), " ")

	if len(args) < 1 {
		if _, err := c.Write([]byte("no arguments passed")); err != nil {
			log.WithError(err).Error("failed to write response")
		}
	}

	switch args[0] {
	case "close-nfqueue-conn":
		if console.packetProcessorRestarter == nil {
			log.Error("no nfqueue connection stored")
			if _, err := c.Write([]byte("no nfqueue connection stored")); err != nil {
				log.WithError(err).Error("failed to write response")
			}
		}

		if err := console.packetProcessorRestarter.DebugKillCurrentNfqueueConnection(); err != nil {
			log.WithError(err).Error("failed to close nfqueue connection file descriptor")
			if _, err := c.Write([]byte("fail: failed to close nfqueue connection file descriptor")); err != nil {
				log.WithError(err).Error("failed to write response")
			}
		}
	default:
		msg := fmt.Sprintf("unknown command %s", args[0])
		if _, err := fmt.Fprintf(c, "fail: %s", msg); err != nil {
			log.WithError(err).Error("failed to write response")
		}
	}

	if _, err := c.Write([]byte("success")); err != nil {
		log.WithError(err).Error("failed to write response")
	}

	if err := c.Close(); err != nil {
		log.WithError(err).Error("failed to close connection")
	}
}

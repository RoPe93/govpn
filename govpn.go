/*
govpn -- high-performance secure virtual private network daemon
Copyright (C) 2014 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"code.google.com/p/go.crypto/poly1305"
	"code.google.com/p/go.crypto/salsa20"
)

var (
	remoteAddr = flag.String("remote", "", "Remote server address")
	bindAddr   = flag.String("bind", "", "Bind to address")
	ifaceName  = flag.String("iface", "tap0", "TAP network interface")
	keyPath    = flag.String("key", "", "Path to authentication key file")
	upPath     = flag.String("up", "", "Path to up-script")
	downPath   = flag.String("down", "", "Path to down-script")
	mtu        = flag.Int("mtu", 1500, "MTU")
	timeoutP   = flag.Int("timeout", 60, "Timeout seconds")
	verboseP   = flag.Bool("v", false, "Increase verbosity")
)

const (
	NonceSize = 8
	KeySize   = 32
	// S20BS is Salsa20's internal blocksize in bytes
	S20BS         = 64
	HeartBeatSize = 12
	HeartBeatMark = "\x00\x00\x00HEARTBEAT"
)

type TAP interface {
	io.Reader
	io.Writer
}

type Peer struct {
	addr      *net.UDPAddr
	key       *[KeySize]byte // encryption key
	nonceOur  uint64         // nonce for our messages
	nonceRecv uint64         // latest received nonce from remote peer
}

type UDPPkt struct {
	addr *net.UDPAddr
	size int
}

func ScriptCall(path *string) {
	if *path == "" {
		return
	}
	cmd := exec.Command(*path, *ifaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		fmt.Println(time.Now(), "script error: ", err.Error(), string(out.Bytes()))
	}
}

func main() {
	flag.Parse()
	timeout := *timeoutP
	verbose := *verboseP
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	// Key decoding
	keyData, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		panic("Unable to read keyfile: " + err.Error())
	}
	if len(keyData) < 64 {
		panic("Key must be 64 hex characters long")
	}
	keyDecoded, err := hex.DecodeString(string(keyData[0:64]))
	if err != nil {
		panic("Unable to decode the key: " + err.Error())
	}
	key := new([KeySize]byte)
	copy(key[:], keyDecoded)
	keyDecoded = nil
	keyData = nil

	// Interface listening
	maxIfacePktSize := *mtu - poly1305.TagSize - NonceSize
	log.Println("Max MTU", maxIfacePktSize, "on interface", *ifaceName)
	iface := NewTAP(*ifaceName)
	ethBuf := make([]byte, maxIfacePktSize)
	ethSink := make(chan int)
	ethSinkReady := make(chan bool)
	go func() {
		for {
			<-ethSinkReady
			n, err := iface.Read(ethBuf)
			if err != nil {
				panic(err)
			}
			ethSink <- n
		}
	}()
	ethSinkReady <- true

	// Network address parsing
	if (len(*bindAddr) > 1 && len(*remoteAddr) > 1) ||
		(len(*bindAddr) == 0 && len(*remoteAddr) == 0) {
		panic("Either -bind or -remote must be specified only")
	}
	var conn *net.UDPConn
	var remote *net.UDPAddr
	serverMode := false
	bindTo := "0.0.0.0:0"

	if len(*bindAddr) > 1 {
		bindTo = *bindAddr
		serverMode = true
	}

	bind, err := net.ResolveUDPAddr("udp", bindTo)
	if err != nil {
		panic(err)
	}
	conn, err = net.ListenUDP("udp", bind)
	if err != nil {
		panic(err)
	}

	if len(*remoteAddr) > 1 {
		remote, err = net.ResolveUDPAddr("udp", *remoteAddr)
		if err != nil {
			panic(err)
		}
	}

	udpBuf := make([]byte, *mtu)
	udpSink := make(chan *UDPPkt)
	udpSinkReady := make(chan bool)
	go func(conn *net.UDPConn) {
		for {
			<-udpSinkReady
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := conn.ReadFromUDP(udpBuf)
			if err != nil {
				if verbose {
					fmt.Print("B")
				}
				udpSink <- nil
			} else {
				udpSink <- &UDPPkt{addr, n}
			}
		}
	}(conn)
	udpSinkReady <- true

	// Process packets
	var udpPkt *UDPPkt
	var udpPktData []byte
	var ethPktSize int
	var frame []byte
	var addr string
	var peer *Peer
	var p *Peer

	timeouts := 0
	states := make(map[string]*Handshake)
	nonce := make([]byte, NonceSize)
	keyAuth := new([KeySize]byte)
	tag := new([poly1305.TagSize]byte)
	buf := make([]byte, *mtu+S20BS)
	emptyKey := make([]byte, KeySize)
	ethPkt := make([]byte, maxIfacePktSize)
	udpPktDataBuf := make([]byte, *mtu)

	if !serverMode {
		states[remote.String()] = HandshakeStart(conn, remote, key)
	}

	heartbeat := time.Tick(time.Second * time.Duration(timeout/3))
	heartbeatMark := []byte(HeartBeatMark)

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	finished := false
	for {
		if finished {
			break
		}
		select {
		case <-termSignal:
			finished = true
		case <-heartbeat:
			go func() { ethSink <- -1 }()
		case udpPkt = <-udpSink:
			timeouts++
			if !serverMode && timeouts >= timeout {
				finished = true
			}
			if udpPkt == nil {
				udpSinkReady <- true
				continue
			}
			copy(udpPktDataBuf, udpBuf[:udpPkt.size])
			udpSinkReady <- true
			udpPktData = udpPktDataBuf[:udpPkt.size]
			if isValidHandshakePkt(udpPktData) {
				addr = udpPkt.addr.String()
				state, exists := states[addr]
				if serverMode {
					if !exists {
						state = &Handshake{addr: udpPkt.addr}
						states[addr] = state
					}
					p = state.Server(conn, key, udpPktData)
				} else {
					if !exists {
						fmt.Print("[HS?]")
						continue
					}
					p = state.Client(conn, key, udpPktData)
				}
				if p != nil {
					fmt.Print("[HS-OK]")
					peer = p
					delete(states, addr)
					go ScriptCall(upPath)
				}
				continue
			}
			if peer == nil {
				continue
			}
			nonceRecv, _ := binary.Uvarint(udpPktData[:8])
			if peer.nonceRecv >= nonceRecv {
				fmt.Print("R")
				continue
			}
			copy(buf[:KeySize], emptyKey)
			copy(tag[:], udpPktData[udpPkt.size-poly1305.TagSize:])
			copy(buf[S20BS:], udpPktData[NonceSize:udpPkt.size-poly1305.TagSize])
			salsa20.XORKeyStream(
				buf[:S20BS+udpPkt.size-poly1305.TagSize],
				buf[:S20BS+udpPkt.size-poly1305.TagSize],
				udpPktData[:NonceSize],
				peer.key,
			)
			copy(keyAuth[:], buf[:KeySize])
			if !poly1305.Verify(tag, udpPktData[:udpPkt.size-poly1305.TagSize], keyAuth) {
				fmt.Print("T")
				continue
			}
			peer.nonceRecv = nonceRecv
			timeouts = 0
			frame = buf[S20BS : S20BS+udpPkt.size-NonceSize-poly1305.TagSize]
			if string(frame[0:HeartBeatSize]) == HeartBeatMark {
				continue
			}
			if _, err := iface.Write(frame); err != nil {
				log.Println("Error writing to iface: ", err)
			}
			if verbose {
				fmt.Print("r")
			}
		case ethPktSize = <-ethSink:
			if ethPktSize > maxIfacePktSize {
				panic("Too large packet on interface")
			}
			if peer == nil {
				ethSinkReady <- true
				continue
			}
			if ethPktSize > -1 {
				copy(ethPkt, ethBuf[:ethPktSize])
				ethSinkReady <- true
			} else {
				copy(ethPkt, heartbeatMark)
				ethPktSize = HeartBeatSize
			}
			peer.nonceOur = peer.nonceOur + 2
			binary.PutUvarint(nonce, peer.nonceOur)
			copy(buf[:KeySize], emptyKey)
			copy(buf[S20BS:], ethPkt[:ethPktSize])
			salsa20.XORKeyStream(buf, buf, nonce, peer.key)
			copy(buf[S20BS-NonceSize:S20BS], nonce)
			copy(keyAuth[:], buf[:KeySize])
			dataToSend := buf[S20BS-NonceSize : S20BS+ethPktSize]
			poly1305.Sum(tag, dataToSend, keyAuth)
			if _, err := conn.WriteTo(append(dataToSend, tag[:]...), peer.addr); err != nil {
				log.Println("Error sending UDP", err)
			}
			if verbose {
				fmt.Print("w")
			}
		}
	}
	ScriptCall(downPath)
}

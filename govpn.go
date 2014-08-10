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
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"code.google.com/p/go.crypto/poly1305"
	"code.google.com/p/go.crypto/salsa20"
	"github.com/chon219/water"
)

const (
	NonceSize    = 8
	AliveTimeout = time.Second * 90
	// S20BS is Salsa20's internal blocksize in bytes
	S20BS = 64
)

type Peer struct {
	addr      *net.UDPAddr
	lastPing  time.Time
	key       *[32]byte // encryption key
	nonceOur  uint64    // nonce for our messages
	nonceRecv uint64    // latest received nonce from remote peer
}

func (p *Peer) IsAlive() bool {
	if (p == nil) || (p.lastPing.Add(AliveTimeout).Before(time.Now())) {
		return false
	}
	return true
}

func (p *Peer) SetAlive() {
	p.lastPing = time.Now()
}

type UDPPkt struct {
	addr *net.UDPAddr
	data []byte
}

var (
	remoteAddr = flag.String("remote", "", "Remote server address")
	bindAddr   = flag.String("bind", "", "Bind to address")
	ifaceName  = flag.String("iface", "tap0", "TAP network interface")
	keyHex     = flag.String("key", "", "Authentication key")
	mtu        = flag.Int("mtu", 1500, "MTU")
	verbose    = flag.Bool("v", false, "Increase verbosity")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	// Key decoding
	if len(*keyHex) != 64 {
		panic("Key is required argument (64 hex characters)")
	}
	keyDecoded, err := hex.DecodeString(*keyHex)
	if err != nil {
		panic(err)
	}
	key := new([32]byte)
	copy(key[:], keyDecoded)

	// Interface listening
	maxIfacePktSize := *mtu - poly1305.TagSize - NonceSize
	log.Println("Max MTU", maxIfacePktSize, "on interface", *ifaceName)
	iface, err := water.NewTAP(*ifaceName)
	if err != nil {
		panic(err)
	}
	ethSink := make(chan []byte)
	go func() {
		for {
			buf := make([]byte, maxIfacePktSize)
			n, err := iface.Read(buf)
			if err != nil {
				panic(err)
			}
			ethSink <- buf[:n]
		}
	}()

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

	udpSink := make(chan UDPPkt)
	go func(conn *net.UDPConn) {
		for {
			data := make([]byte, *mtu)
			n, addr, err := conn.ReadFromUDP(data)
			if err != nil {
				fmt.Print("B")
			}
			udpSink <- UDPPkt{addr, data[:n]}
		}
	}(conn)

	// Process packets
	var udpPkt UDPPkt
	var ethPkt []byte
	var addr string
	var peer Peer
	var p *Peer
	var buf []byte

	states := make(map[string]*Handshake)
	nonce := make([]byte, NonceSize)
	keyAuth := new([32]byte)
	tag := new([poly1305.TagSize]byte)

	if !serverMode {
		log.Println("starting handshake with", *remoteAddr)
		states[remote.String()] = HandshakeStart(conn, remote, key)
	}

	for {
		buf = make([]byte, *mtu+S20BS)
		select {
		case udpPkt = <-udpSink:
			if isValidHandshakePkt(udpPkt.data) {
				addr = udpPkt.addr.String()
				state, exists := states[addr]
				if serverMode {
					if !exists {
						state = &Handshake{addr: udpPkt.addr}
						states[addr] = state
					}
					p = state.Server(conn, key, udpPkt.data)
				} else {
					if !exists {
						fmt.Print("[HS?]")
						continue
					}
					p = state.Client(conn, key, udpPkt.data)
				}
				if p != nil {
					fmt.Print("[HS-OK]")
					peer = *p
					delete(states, addr)
				}
				continue
			}
			if !peer.IsAlive() {
				continue
			}
			nonceRecv, _ := binary.Uvarint(udpPkt.data[:8])
			if peer.nonceRecv >= nonceRecv {
				fmt.Print("R")
				continue
			}
			copy(tag[:], udpPkt.data[len(udpPkt.data)-poly1305.TagSize:])
			copy(buf[S20BS:], udpPkt.data[NonceSize:len(udpPkt.data)-poly1305.TagSize])
			salsa20.XORKeyStream(
				buf[:S20BS+len(udpPkt.data)-poly1305.TagSize],
				buf[:S20BS+len(udpPkt.data)-poly1305.TagSize],
				udpPkt.data[:NonceSize],
				peer.key,
			)
			copy(keyAuth[:], buf[:32])
			if !poly1305.Verify(tag, udpPkt.data[:len(udpPkt.data)-poly1305.TagSize], keyAuth) {
				fmt.Print("T")
				continue
			}
			peer.nonceRecv = nonceRecv
			peer.SetAlive()
			if _, err := iface.Write(buf[S20BS : S20BS+len(udpPkt.data)-NonceSize-poly1305.TagSize]); err != nil {
				log.Println("Error writing to iface")
			}
			if *verbose {
				fmt.Print("r")
			}
		case ethPkt = <-ethSink:
			if len(ethPkt) > maxIfacePktSize {
				panic("Too large packet on interface")
			}
			if !peer.IsAlive() {
				continue
			}
			peer.nonceOur = peer.nonceOur + 2
			binary.PutUvarint(nonce, peer.nonceOur)
			copy(buf[S20BS:], ethPkt)
			salsa20.XORKeyStream(buf, buf, nonce, peer.key)
			copy(buf[S20BS-NonceSize:S20BS], nonce)
			copy(keyAuth[:], buf[:32])
			dataToSend := buf[S20BS-NonceSize : S20BS+len(ethPkt)]
			poly1305.Sum(tag, dataToSend, keyAuth)
			if _, err := conn.WriteToUDP(append(dataToSend, tag[:]...), peer.addr); err != nil {
				log.Println("Error sending UDP", err)
			}
			if *verbose {
				fmt.Print("w")
			}
		}
	}
}

/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>

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

// Simple secure free software virtual private network daemon.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	"govpn"
)

var (
	remoteAddr = flag.String("remote", "", "Remote server address")
	ifaceName  = flag.String("iface", "tap0", "TAP network interface")
	IDRaw      = flag.String("id", "", "Client identification")
	keyPath    = flag.String("key", "", "Path to authentication key file")
	upPath     = flag.String("up", "", "Path to up-script")
	downPath   = flag.String("down", "", "Path to down-script")
	mtu        = flag.Int("mtu", 1500, "MTU")
	nonceDiff  = flag.Int("noncediff", 1, "Allow nonce difference")
	timeoutP   = flag.Int("timeout", 60, "Timeout seconds")
)

func main() {
	flag.Parse()
	timeout := *timeoutP
	var err error
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	govpn.MTU = *mtu
	govpn.Timeout = timeout
	govpn.Noncediff = *nonceDiff

	id := govpn.IDDecode(*IDRaw)
	key := govpn.KeyRead(*keyPath)
	if id == nil {
		panic("ID is not specified")
	}

	bind, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		panic(err)
	}
	remote, err := net.ResolveUDPAddr("udp", *remoteAddr)
	if err != nil {
		panic(err)
	}

	tap, ethSink, ethReady, _, err := govpn.TAPListen(*ifaceName)
	if err != nil {
		panic(err)
	}
	udpSink, udpBuf, udpReady := govpn.ConnListen(conn)

	timeouts := 0
	firstUpCall := true
	var peer *govpn.Peer
	var ethPkt []byte
	var udpPkt *govpn.UDPPkt
	var udpPktData []byte

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	log.Println("Client version", govpn.Version)
	log.Println("Starting handshake")
	handshake := govpn.HandshakeStart(conn, remote, id, key)

MainCycle:
	for {
		if peer != nil && peer.Bytes > govpn.MaxBytesPerKey {
			peer = nil
			handshake = govpn.HandshakeStart(conn, remote, id, key)
			log.Println("Rehandshaking")
		}
		select {
		case <-termSignal:
			break MainCycle
		case ethPkt = <-ethSink:
			if peer == nil {
				ethReady <- struct{}{}
				continue
			}
			peer.EthProcess(ethPkt, conn, ethReady)
		case udpPkt = <-udpSink:
			timeouts++
			if timeouts >= timeout {
				break MainCycle
			}
			if udpPkt == nil {
				udpReady <- struct{}{}
				continue
			}

			udpPktData = udpBuf[:udpPkt.Size]
			if govpn.IsValidHandshakePkt(udpPktData) {
				if udpPkt.Addr.String() != remote.String() {
					udpReady <- struct{}{}
					log.Println("Unknown handshake message")
					continue
				}
				if p := handshake.Client(conn, key, udpPktData); p != nil {
					log.Println("Handshake completed")
					if firstUpCall {
						go govpn.ScriptCall(*upPath, *ifaceName)
						firstUpCall = false
					}
					peer = p
					handshake = nil
				}
				udpReady <- struct{}{}
				continue
			}
			if peer == nil {
				udpReady <- struct{}{}
				continue
			}
			if peer.UDPProcess(udpPktData, tap, udpReady) {
				timeouts = 0
			}
		}
	}
	govpn.ScriptCall(*downPath, *ifaceName)
}

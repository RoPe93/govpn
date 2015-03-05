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
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"time"

	"govpn"
)

var (
	bindAddr  = flag.String("bind", "[::]:1194", "Bind to address")
	peersPath = flag.String("peers", "peers", "Path to peers keys directory")
	mtu       = flag.Int("mtu", 1500, "MTU")
	nonceDiff = flag.Int("noncediff", 1, "Allow nonce difference")
	timeoutP  = flag.Int("timeout", 60, "Timeout seconds")
)

type PeerReadyEvent struct {
	peer  *govpn.Peer
	iface string
}

type PeerState struct {
	peer      *govpn.Peer
	tap       *govpn.TAP
	sink      chan []byte
	ready     chan struct{}
	terminate chan struct{}
}

func NewPeerState(peer *govpn.Peer, iface string) *PeerState {
	tap, sink, ready, terminate, err := govpn.TAPListen(iface)
	if err != nil {
		log.Println("Unable to create Eth", err)
		return nil
	}
	state := PeerState{
		peer:      peer,
		tap:       tap,
		sink:      sink,
		ready:     ready,
		terminate: terminate,
	}
	return &state
}

type EthEvent struct {
	peer  *govpn.Peer
	data  []byte
	ready chan struct{}
}

func main() {
	flag.Parse()
	timeout := time.Second * time.Duration(*timeoutP)
	var err error
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	govpn.MTU = *mtu
	govpn.Timeout = *timeoutP
	govpn.Noncediff = *nonceDiff
	govpn.PeersInit(*peersPath)

	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		panic(err)
	}
	udpSink, udpBuf, udpReady := govpn.ConnListen(conn)

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	var addr string
	var state *govpn.Handshake
	var peerState *PeerState
	var peer *govpn.Peer
	var exists bool
	states := make(map[string]*govpn.Handshake)
	peers := make(map[string]*PeerState)
	peerReadySink := make(chan PeerReadyEvent)
	var peerReady PeerReadyEvent
	var udpPkt *govpn.UDPPkt
	var udpPktData []byte
	var ethEvent EthEvent
	ethSink := make(chan EthEvent)

	log.Println("Server version", govpn.Version)
	log.Println("Server started")

MainCycle:
	for {
		select {
		case <-termSignal:
			break MainCycle
		case <-hsHeartbeat:
			now := time.Now()
			for addr, hs := range states {
				if hs.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting handshake state", addr)
					delete(states, addr)
				}
			}
			for addr, state := range peers {
				if state.peer.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting peer", state.peer)
					delete(peers, addr)
					downPath := path.Join(
						govpn.PeersPath,
						state.peer.Id.String(),
						"down.sh",
					)
					go govpn.ScriptCall(downPath, state.tap.Name)
					state.terminate <- struct{}{}
				}
			}
		case peerReady = <-peerReadySink:
			for addr, state := range peers {
				if state.tap.Name != peerReady.iface {
					continue
				}
				delete(peers, addr)
				state.terminate <- struct{}{}
				break
			}
			addr = peerReady.peer.Addr.String()
			state := NewPeerState(peerReady.peer, peerReady.iface)
			if state == nil {
				continue
			}
			peers[addr] = state
			delete(states, addr)
			log.Println("Registered interface", peerReady.iface, "with peer", peer)
			go func(state *PeerState) {
				for data := range state.sink {
					ethSink <- EthEvent{
						peer:  state.peer,
						data:  data,
						ready: state.ready,
					}
				}
			}(state)
		case ethEvent = <-ethSink:
			if _, exists := peers[ethEvent.peer.Addr.String()]; !exists {
				continue
			}
			ethEvent.peer.EthProcess(ethEvent.data, conn, ethEvent.ready)
		case udpPkt = <-udpSink:
			if udpPkt == nil {
				udpReady <- struct{}{}
				continue
			}
			udpPktData = udpBuf[:udpPkt.Size]
			addr = udpPkt.Addr.String()
			if govpn.IsValidHandshakePkt(udpPktData) {
				state, exists = states[addr]
				if !exists {
					state = govpn.HandshakeNew(udpPkt.Addr)
					states[addr] = state
				}
				peer = state.Server(conn, udpPktData)
				if peer != nil {
					log.Println("Peer handshake finished", peer)
					if _, exists = peers[addr]; exists {
						go func() {
							peerReadySink <- PeerReadyEvent{peer, peers[addr].tap.Name}
						}()
					} else {
						go func() {
							upPath := path.Join(govpn.PeersPath, peer.Id.String(), "up.sh")
							result, err := govpn.ScriptCall(upPath, "")
							if err != nil {
								return
							}
							sepIndex := bytes.Index(result, []byte{'\n'})
							if sepIndex < 0 {
								sepIndex = len(result)
							}
							ifaceName := string(result[:sepIndex])
							peerReadySink <- PeerReadyEvent{peer, ifaceName}
						}()
					}
				}
				udpReady <- struct{}{}
				continue
			}
			peerState, exists = peers[addr]
			if !exists {
				udpReady <- struct{}{}
				continue
			}
			peerState.peer.UDPProcess(udpPktData, peerState.tap, udpReady)
		}
	}
}

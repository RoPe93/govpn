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

package govpn

import (
	"crypto/subtle"
	"encoding/binary"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/xtea"
)

const (
	NonceSize = 8
	KeySize   = 32
	// S20BS is Salsa20's internal blocksize in bytes
	S20BS         = 64
	HeartbeatSize = 12
	// Maximal amount of bytes transfered with single key (4 GiB)
	MaxBytesPerKey = 4294967296
)

type UDPPkt struct {
	Addr *net.UDPAddr
	Size int
}

type Peer struct {
	Addr        *net.UDPAddr
	Id          PeerId
	Key         *[KeySize]byte // encryption key
	NonceOur    uint64         // nonce for our messages
	NonceRecv   uint64         // latest received nonce from remote peer
	NonceCipher *xtea.Cipher   // nonce cipher
	LastPing    time.Time
	LastSent    time.Time
	buf         []byte
	tag         *[poly1305.TagSize]byte
	keyAuth     *[KeySize]byte
	nonceRecv   uint64
	Bytes       int
	frame       []byte
	nonce       []byte
}

func (p *Peer) String() string {
	return p.Id.String() + ":" + p.Addr.String()
}

var (
	HeartbeatMark   = []byte("\x00\x00\x00HEARTBEAT")
	Emptiness       = make([]byte, KeySize)
	taps            = make(map[string]*TAP)
	heartbeatPeriod *time.Duration
)

func heartbeatPeriodGet() time.Duration {
	if heartbeatPeriod == nil {
		period := time.Second * time.Duration(Timeout/4)
		heartbeatPeriod = &period
	}
	return *heartbeatPeriod
}

// Create TAP listening goroutine.
// This function takes required TAP interface name, opens it and allocates
// a buffer where all frame data will be written, channel where information
// about number of read bytes is sent to, synchronization channel (external
// processes tell that read buffer can be used again) and possible channel
// opening error.
func TAPListen(ifaceName string) (*TAP, chan []byte, chan struct{}, chan struct{}, error) {
	var tap *TAP
	var err error
	tap, exists := taps[ifaceName]
	if !exists {
		tap, err = NewTAP(ifaceName)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		taps[ifaceName] = tap
	}
	sink := make(chan []byte)
	sinkReady := make(chan struct{})
	sinkTerminate := make(chan struct{})

	go func() {
		heartbeat := time.Tick(heartbeatPeriodGet())
		var pkt []byte
	ListenCycle:
		for {
			select {
			case <-sinkTerminate:
				break ListenCycle
			case <-heartbeat:
				sink <- make([]byte, 0)
				continue
			case <-sinkReady:
				if exists {
					exists = false
					break
				}
				tap.ready <- struct{}{}
			}
		HeartbeatCatched:
			select {
			case <-heartbeat:
				sink <- make([]byte, 0)
				goto HeartbeatCatched
			case <-sinkTerminate:
				break ListenCycle
			case pkt = <-tap.sink:
				sink <- pkt
			}
		}
		close(sink)
	}()
	sinkReady <- struct{}{}
	return tap, sink, sinkReady, sinkTerminate, nil
}

// Create UDP listening goroutine.
// This function takes already listening UDP socket and a buffer where
// all UDP packet data will be saved, channel where information about
// remote address and number of written bytes are stored, and a channel
// used to tell that buffer is ready to be overwritten.
func ConnListen(conn *net.UDPConn) (chan *UDPPkt, []byte, chan struct{}) {
	buf := make([]byte, MTU)
	sink := make(chan *UDPPkt)
	sinkReady := make(chan struct{})
	go func(conn *net.UDPConn) {
		var n int
		var addr *net.UDPAddr
		var err error
		for {
			<-sinkReady
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err = conn.ReadFromUDP(buf)
			if err != nil {
				// This is needed for ticking the timeouts counter outside
				sink <- nil
				continue
			}
			sink <- &UDPPkt{addr, n}
		}
	}(conn)
	sinkReady <- struct{}{}
	return sink, buf, sinkReady
}

func newNonceCipher(key *[KeySize]byte) *xtea.Cipher {
	nonceKey := make([]byte, 16)
	salsa20.XORKeyStream(nonceKey, make([]byte, KeySize), make([]byte, xtea.BlockSize), key)
	ciph, err := xtea.NewCipher(nonceKey)
	if err != nil {
		panic(err)
	}
	return ciph
}

func newPeer(addr *net.UDPAddr, id PeerId, nonce int, key *[KeySize]byte) *Peer {
	peer := Peer{
		Addr:        addr,
		LastPing:    time.Now(),
		Id:          id,
		NonceOur:    uint64(Noncediff + nonce),
		NonceRecv:   uint64(Noncediff + 0),
		Key:         key,
		NonceCipher: newNonceCipher(key),
		Bytes:       0,
		buf:         make([]byte, MTU+S20BS),
		tag:         new([poly1305.TagSize]byte),
		keyAuth:     new([KeySize]byte),
		nonce:       make([]byte, NonceSize),
	}
	return &peer
}

// Process incoming UDP packet.
// udpPkt is received data, related to the peer tap interface and
// ConnListen'es synchronization channel used to tell him that he is
// free to receive new packets. Authenticated and decrypted packets
// will be written to the interface immediately (except heartbeat ones).
func (p *Peer) UDPProcess(udpPkt []byte, tap *TAP, ready chan struct{}) bool {
	size := len(udpPkt)
	copy(p.buf[:KeySize], Emptiness)
	copy(p.tag[:], udpPkt[size-poly1305.TagSize:])
	copy(p.buf[S20BS:], udpPkt[NonceSize:size-poly1305.TagSize])
	salsa20.XORKeyStream(
		p.buf[:S20BS+size-poly1305.TagSize],
		p.buf[:S20BS+size-poly1305.TagSize],
		udpPkt[:NonceSize],
		p.Key,
	)
	copy(p.keyAuth[:], p.buf[:KeySize])
	if !poly1305.Verify(p.tag, udpPkt[:size-poly1305.TagSize], p.keyAuth) {
		ready <- struct{}{}
		return false
	}
	p.NonceCipher.Decrypt(p.buf, udpPkt[:NonceSize])
	p.nonceRecv, _ = binary.Uvarint(p.buf[:NonceSize])
	if int(p.NonceRecv)-Noncediff >= 0 && int(p.nonceRecv) < int(p.NonceRecv)-Noncediff {
		ready <- struct{}{}
		return false
	}
	ready <- struct{}{}
	p.LastPing = time.Now()
	p.NonceRecv = p.nonceRecv
	p.frame = p.buf[S20BS : S20BS+size-NonceSize-poly1305.TagSize]
	p.Bytes += len(p.frame)
	if subtle.ConstantTimeCompare(p.frame[:HeartbeatSize], HeartbeatMark) == 1 {
		return true
	}
	tap.Write(p.frame)
	return true
}

// Process incoming Ethernet packet.
// ethPkt is received data, conn is our outgoing connection.
// ready channel is TAPListen's synchronization channel used to tell him
// that he is free to receive new packets. Encrypted and authenticated
// packets will be sent to remote Peer side immediately.
func (p *Peer) EthProcess(ethPkt []byte, conn *net.UDPConn, ready chan struct{}) {
	now := time.Now()
	size := len(ethPkt)
	// If this heartbeat is necessary
	if size == 0 && !p.LastSent.Add(heartbeatPeriodGet()).Before(now) {
		return
	}
	copy(p.buf[:KeySize], Emptiness)
	if size > 0 {
		copy(p.buf[S20BS:], ethPkt)
		ready <- struct{}{}
	} else {
		copy(p.buf[S20BS:], HeartbeatMark)
		size = HeartbeatSize
	}

	p.NonceOur = p.NonceOur + 2
	copy(p.nonce, Emptiness)
	binary.PutUvarint(p.nonce, p.NonceOur)
	p.NonceCipher.Encrypt(p.nonce, p.nonce)

	salsa20.XORKeyStream(p.buf, p.buf, p.nonce, p.Key)
	copy(p.buf[S20BS-NonceSize:S20BS], p.nonce)
	copy(p.keyAuth[:], p.buf[:KeySize])
	p.frame = p.buf[S20BS-NonceSize : S20BS+size]
	poly1305.Sum(p.tag, p.frame, p.keyAuth)

	p.Bytes += len(p.frame)
	p.LastSent = now
	if _, err := conn.WriteTo(append(p.frame, p.tag[:]...), p.Addr); err != nil {
		log.Println("Error sending UDP", err)
	}
}

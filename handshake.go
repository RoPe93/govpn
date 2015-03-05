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
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"log"
	"net"
	"path"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/xtea"
)

type Handshake struct {
	addr     *net.UDPAddr
	LastPing time.Time
	Id       PeerId
	rNonce   *[8]byte
	dhPriv   *[32]byte      // own private DH key
	key      *[KeySize]byte // handshake encryption key
	rServer  *[8]byte       // random string for authentication
	rClient  *[8]byte
	sServer  *[32]byte // secret string for main key calculation
	sClient  *[32]byte
}

func keyFromSecrets(server, client []byte) *[KeySize]byte {
	k := new([32]byte)
	for i := 0; i < 32; i++ {
		k[i] = server[i] ^ client[i]
	}
	return k
}

// Check if it is valid handshake-related message.
// Minimal size and last 16 zero bytes.
func IsValidHandshakePkt(pkt []byte) bool {
	if len(pkt) < 24 {
		return false
	}
	for i := len(pkt) - poly1305.TagSize; i < len(pkt); i++ {
		if pkt[i] != '\x00' {
			return false
		}
	}
	return true
}

func (h *Handshake) rNonceNext() []byte {
	nonce := make([]byte, 8)
	nonceCurrent, _ := binary.Uvarint(h.rNonce[:])
	binary.PutUvarint(nonce, nonceCurrent+1)
	return nonce
}

func dhPrivGen() *[32]byte {
	dh := new([32]byte)
	if _, err := rand.Read(dh[:]); err != nil {
		panic("Can not read random for DH private key")
	}
	return dh
}

func dhKeyGen(priv, pub *[32]byte) *[32]byte {
	key := new([32]byte)
	curve25519.ScalarMult(key, priv, pub)
	salsa.HSalsa20(key, new([16]byte), key, &salsa.Sigma)
	return key
}

// Create new handshake state.
func HandshakeNew(addr *net.UDPAddr) *Handshake {
	state := Handshake{
		addr:     addr,
		LastPing: time.Now(),
	}
	return &state
}

// Start handshake's procedure from the client.
// It is the entry point for starting the handshake procedure.
// You have to specify outgoing conn address, remote's addr address,
// our own identification and an encryption key. First handshake packet
// will be sent immediately.
func HandshakeStart(conn *net.UDPConn, addr *net.UDPAddr, id *PeerId, key *[32]byte) *Handshake {
	state := HandshakeNew(addr)

	state.dhPriv = dhPrivGen()
	dhPub := new([32]byte)
	curve25519.ScalarBaseMult(dhPub, state.dhPriv)

	state.rNonce = new([8]byte)
	if _, err := rand.Read(state.rNonce[:]); err != nil {
		panic("Can not read random for handshake nonce")
	}
	enc := make([]byte, 32)
	salsa20.XORKeyStream(enc, dhPub[:], state.rNonce[:], key)

	ciph, err := xtea.NewCipher(id[:])
	if err != nil {
		panic(err)
	}
	rEnc := make([]byte, xtea.BlockSize)
	ciph.Encrypt(rEnc, state.rNonce[:])

	data := append(state.rNonce[:], enc...)
	data = append(data, rEnc...)
	data = append(data, '\x00')
	data = append(data, make([]byte, poly1305.TagSize)...)

	if _, err := conn.WriteTo(data, addr); err != nil {
		panic(err)
	}
	return state
}

// Process handshake message on the server side.
// This function is intended to be called on server's side.
// Our outgoing conn connection and received data are required.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Server(conn *net.UDPConn, data []byte) *Peer {
	switch len(data) {
	case 65: // R + ENC(PSK, dh_client_pub) + xtea(ID, R) + NULL + NULLs
		if h.rNonce != nil {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Try to determine client's ID
		id := IDsCache.Find(data[:8], data[8+32:8+32+8])
		if id == nil {
			log.Println("Unknown identity from", h.addr)
			return nil
		}
		key := KeyRead(path.Join(PeersPath, id.String(), "key"))
		h.Id = *id

		// Generate private DH key
		h.dhPriv = dhPrivGen()
		dhPub := new([32]byte)
		curve25519.ScalarBaseMult(dhPub, h.dhPriv)

		// Decrypt remote public key and compute shared key
		dec := new([32]byte)
		salsa20.XORKeyStream(dec[:], data[8:8+32], data[:8], key)
		h.key = dhKeyGen(h.dhPriv, dec)

		// Compute nonce and encrypt our public key
		h.rNonce = new([8]byte)
		copy(h.rNonce[:], data[:8])

		encPub := make([]byte, 32)
		salsa20.XORKeyStream(encPub, dhPub[:], h.rNonceNext(), key)

		// Generate R* and encrypt them
		h.rServer = new([8]byte)
		if _, err := rand.Read(h.rServer[:]); err != nil {
			panic("Can not read random for handshake random key")
		}
		h.sServer = new([32]byte)
		if _, err := rand.Read(h.sServer[:]); err != nil {
			panic("Can not read random for handshake shared key")
		}
		encRs := make([]byte, 8+32)
		salsa20.XORKeyStream(encRs, append(h.rServer[:], h.sServer[:]...), h.rNonce[:], h.key)

		// Send that to client
		if _, err := conn.WriteTo(
			append(encPub,
				append(encRs, make([]byte, poly1305.TagSize)...)...), h.addr); err != nil {
			panic(err)
		}
		h.LastPing = time.Now()
	case 64: // ENC(K, RS + RC + SC) + NULLs
		if (h.rNonce == nil) || (h.rClient != nil) {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Decrypted Rs compare rServer
		decRs := make([]byte, 8+8+32)
		salsa20.XORKeyStream(decRs, data[:8+8+32], h.rNonceNext(), h.key)
		if subtle.ConstantTimeCompare(decRs[:8], h.rServer[:]) != 1 {
			log.Println("Invalid server's random number with", h.addr)
			return nil
		}

		// Send final answer to client
		enc := make([]byte, 8)
		salsa20.XORKeyStream(enc, decRs[8:8+8], make([]byte, 8), h.key)
		if _, err := conn.WriteTo(append(enc, make([]byte, poly1305.TagSize)...), h.addr); err != nil {
			panic(err)
		}

		// Switch peer
		peer := newPeer(h.addr, h.Id, 0, keyFromSecrets(h.sServer[:], decRs[8+8:]))
		h.LastPing = time.Now()
		return peer
	default:
		log.Println("Invalid handshake message from", h.addr)
	}
	return nil
}

// Process handshake message on the client side.
// This function is intended to be called on client's side.
// Our outgoing conn connection, authentication key and received data
// are required. Client does not work with identities, as he is the
// only one, so key is a requirement.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Client(conn *net.UDPConn, key *[KeySize]byte, data []byte) *Peer {
	switch len(data) {
	case 88: // ENC(PSK, dh_server_pub) + ENC(K, RS + SS) + NULLs
		if h.key != nil {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Decrypt remote public key and compute shared key
		dec := new([32]byte)
		salsa20.XORKeyStream(dec[:], data[:32], h.rNonceNext(), key)
		h.key = dhKeyGen(h.dhPriv, dec)

		// Decrypt Rs
		decRs := make([]byte, 8+32)
		salsa20.XORKeyStream(decRs, data[32:32+8+32], h.rNonce[:], h.key)
		h.rServer = new([8]byte)
		copy(h.rServer[:], decRs[:8])
		h.sServer = new([32]byte)
		copy(h.sServer[:], decRs[8:])

		// Generate R* and encrypt them
		h.rClient = new([8]byte)
		if _, err := rand.Read(h.rClient[:]); err != nil {
			panic("Can not read random for handshake random key")
		}
		h.sClient = new([32]byte)
		if _, err := rand.Read(h.sClient[:]); err != nil {
			panic("Can not read random for handshake shared key")
		}
		encRs := make([]byte, 8+8+32)
		salsa20.XORKeyStream(encRs,
			append(h.rServer[:],
				append(h.rClient[:], h.sClient[:]...)...), h.rNonceNext(), h.key)

		// Send that to server
		if _, err := conn.WriteTo(append(encRs, make([]byte, poly1305.TagSize)...), h.addr); err != nil {
			panic(err)
		}
		h.LastPing = time.Now()
	case 24: // ENC(K, RC) + NULLs
		if h.key == nil {
			log.Println("Invalid handshake stage from", h.addr)
			return nil
		}

		// Decrypt rClient
		dec := make([]byte, 8)
		salsa20.XORKeyStream(dec, data[:8], make([]byte, 8), h.key)
		if subtle.ConstantTimeCompare(dec, h.rClient[:]) != 1 {
			log.Println("Invalid client's random number with", h.addr)
			return nil
		}

		// Switch peer
		peer := newPeer(h.addr, h.Id, 1, keyFromSecrets(h.sServer[:], h.sClient[:]))
		h.LastPing = time.Now()
		return peer
	default:
		log.Println("Invalid handshake message from", h.addr)
	}
	return nil
}

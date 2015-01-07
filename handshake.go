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
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/poly1305"
	"code.google.com/p/go.crypto/salsa20"
	"code.google.com/p/go.crypto/salsa20/salsa"
)

type Handshake struct {
	addr     *net.UDPAddr
	lastPing time.Time
	rNonce   *[8]byte
	dhPriv   *[32]byte // own private DH key
	key      *[32]byte // handshake encryption key
	rServer  *[8]byte  // random string for authentication
	rClient  *[8]byte
	sServer  *[32]byte // secret string for main key calculation
	sClient  *[32]byte
}

func KeyFromSecrets(server, client []byte) *[32]byte {
	k := new([32]byte)
	for i := 0; i < 32; i++ {
		k[i] = server[i] ^ client[i]
	}
	return k
}

// Check if it is valid handshake-related message
// Minimal size and last 16 zero bytes
func isValidHandshakePkt(pkt []byte) bool {
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

func HandshakeStart(conn *net.UDPConn, addr *net.UDPAddr, key *[32]byte) *Handshake {
	state := Handshake{}
	state.addr = addr
	state.lastPing = time.Now()

	state.dhPriv = dhPrivGen()
	dhPub := new([32]byte)
	curve25519.ScalarBaseMult(dhPub, state.dhPriv)

	state.rNonce = new([8]byte)
	if _, err := rand.Read(state.rNonce[:]); err != nil {
		panic("Can not read random for handshake nonce")
	}
	enc := make([]byte, 32)
	salsa20.XORKeyStream(enc, dhPub[:], state.rNonce[:], key)

	if _, err := conn.WriteTo(
		append(state.rNonce[:],
			append(enc, make([]byte, poly1305.TagSize)...)...), addr); err != nil {
		panic(err)
	}
	return &state
}

func (h *Handshake) Server(conn *net.UDPConn, key *[32]byte, data []byte) *Peer {
	switch len(data) {
	case 56: // R + ENC(PSK, dh_client_pub) + NULLs
		fmt.Print("[HS1]")
		if h.rNonce != nil {
			fmt.Print("[S?]")
			return nil
		}

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
		fmt.Print("[OK]")
	case 64: // ENC(K, RS + RC + SC) + NULLs
		fmt.Print("[HS3]")
		if (h.rNonce == nil) || (h.rClient != nil) {
			fmt.Print("[S?]")
			return nil
		}

		// Decrypt Rs compare rServer
		decRs := make([]byte, 8+8+32)
		salsa20.XORKeyStream(decRs, data[:8+8+32], h.rNonceNext(), h.key)
		if res := subtle.ConstantTimeCompare(decRs[:8], h.rServer[:]); res != 1 {
			fmt.Print("[rS?]")
			return nil
		}

		// Send final answer to client
		enc := make([]byte, 8)
		salsa20.XORKeyStream(enc, decRs[8:8+8], make([]byte, 8), h.key)
		if _, err := conn.WriteTo(append(enc, make([]byte, poly1305.TagSize)...), h.addr); err != nil {
			panic(err)
		}

		// Switch peer
		peer := Peer{addr: h.addr, nonceOur: 0, nonceRecv: 0}
		peer.key = KeyFromSecrets(h.sServer[:], decRs[8+8:])
		fmt.Print("[OK]")
		return &peer
	default:
		fmt.Print("[HS?]")
	}
	return nil
}

func (h *Handshake) Client(conn *net.UDPConn, key *[32]byte, data []byte) *Peer {
	switch len(data) {
	case 88: // ENC(PSK, dh_server_pub) + ENC(K, RS + SS) + NULLs
		fmt.Print("[HS2]")
		if h.key != nil {
			fmt.Print("[S?]")
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
		fmt.Print("[OK]")
	case 24: // ENC(K, RC) + NULLs
		fmt.Print("[HS4]")
		if h.key == nil {
			fmt.Print("[S?]")
			return nil
		}

		// Decrypt rClient
		dec := make([]byte, 8)
		salsa20.XORKeyStream(dec, data[:8], make([]byte, 8), h.key)
		if res := subtle.ConstantTimeCompare(dec, h.rClient[:]); res != 1 {
			fmt.Print("[rC?]")
			return nil
		}

		// Switch peer
		peer := Peer{addr: h.addr, nonceOur: 1, nonceRecv: 0}
		peer.key = KeyFromSecrets(h.sServer[:], h.sClient[:])
		fmt.Print("[OK]")
		return &peer
	default:
		fmt.Print("[HS?]")
	}
	return nil
}

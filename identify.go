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
	"encoding/hex"
	"log"
	"os"

	"golang.org/x/crypto/xtea"
)

const (
	IDSize = 128 / 8
)

type PeerId [IDSize]byte

func (id PeerId) String() string {
	return hex.EncodeToString(id[:])
}

type cipherCache map[PeerId]*xtea.Cipher

var (
	PeersPath string
	IDsCache  cipherCache
)

// Initialize (pre-cache) available peers info.
func PeersInit(path string) {
	PeersPath = path
	IDsCache = make(map[PeerId]*xtea.Cipher)
	IDsCache.refresh()
}

// Refresh IDsCache: remove disappeared keys, add missing ones with
// initialized ciphers.
func (cc cipherCache) refresh() {
	dir, err := os.Open(PeersPath)
	if err != nil {
		panic(err)
	}
	peerIds, err := dir.Readdirnames(0)
	if err != nil {
		panic(err)
	}
	available := make(map[PeerId]bool)
	for _, peerId := range peerIds {
		id := IDDecode(peerId)
		if id == nil {
			continue
		}
		available[*id] = true
	}
	// Cleanup deleted ones from cache
	for k, _ := range cc {
		if _, exists := available[k]; !exists {
			delete(cc, k)
			log.Println("Cleaning key: ", k)
		}
	}
	// Add missing ones
	for peerId, _ := range available {
		if _, exists := cc[peerId]; !exists {
			log.Println("Adding key", peerId)
			cipher, err := xtea.NewCipher(peerId[:])
			if err != nil {
				panic(err)
			}
			cc[peerId] = cipher
		}
	}
}

// Try to find peer's identity (that equals to an encryption key)
// by providing cipher and plain texts.
func (cc cipherCache) Find(plaintext, ciphertext []byte) *PeerId {
	cc.refresh()
	buf := make([]byte, xtea.BlockSize)
	for pid, cipher := range cc {
		cipher.Decrypt(buf, ciphertext)
		if subtle.ConstantTimeCompare(buf, plaintext) == 1 {
			ppid := PeerId(pid)
			return &ppid
		}
	}
	return nil
}

// Decode identification string.
// It must be 32 hexadecimal characters long.
// If it is not the valid one, then return nil.
func IDDecode(raw string) *PeerId {
	if len(raw) != IDSize*2 {
		return nil
	}
	idDecoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil
	}
	idP := new([IDSize]byte)
	copy(idP[:], idDecoded)
	id := PeerId(*idP)
	return &id
}

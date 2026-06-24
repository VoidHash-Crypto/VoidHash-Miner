// Package voidhash implements the VoidHash proof-of-work algorithm.
// This is a self-contained copy for use in the standalone miner.
package voidhash

import (
	"encoding/binary"
	"math/bits"
)

// ── Tweaked Keccak constants ──────────────────────────────────────────────────

const domainTag = uint64(0xC0DE_FA1C_0B10_CAFE)

var voidRC = [24]uint64{
	0x0000000000000001 ^ domainTag, 0x0000000000008082 ^ domainTag,
	0x800000000000808A ^ domainTag, 0x8000000080008000 ^ domainTag,
	0x000000000000808B ^ domainTag, 0x0000000080000001 ^ domainTag,
	0x8000000080008081 ^ domainTag, 0x8000000000008009 ^ domainTag,
	0x000000000000008A ^ domainTag, 0x0000000000000088 ^ domainTag,
	0x0000000080008009 ^ domainTag, 0x000000008000000A ^ domainTag,
	0x000000008000808B ^ domainTag, 0x800000000000008B ^ domainTag,
	0x8000000000008089 ^ domainTag, 0x8000000000008003 ^ domainTag,
	0x8000000000008002 ^ domainTag, 0x8000000000000080 ^ domainTag,
	0x000000000000800A ^ domainTag, 0x800000008000000A ^ domainTag,
	0x8000000080008081 ^ domainTag, 0x8000000000008080 ^ domainTag,
	0x0000000080000001 ^ domainTag, 0x8000000080008008 ^ domainTag,
}

var rho = [25]uint{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}
var pi = [25]int{0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4}

func keccakF(a *[25]uint64) {
	var bc [5]uint64
	var t uint64
	for r := 0; r < 24; r++ {
		for x := 0; x < 5; x++ {
			bc[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			t = bc[(x+4)%5] ^ bits.RotateLeft64(bc[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[y+x] ^= t
			}
		}
		var b [25]uint64
		for i := 0; i < 25; i++ {
			b[pi[i]] = bits.RotateLeft64(a[i], int(rho[i]))
		}
		for y := 0; y < 25; y += 5 {
			for x := 0; x < 5; x++ {
				a[y+x] = b[y+x] ^ ((^b[y+(x+1)%5]) & b[y+(x+2)%5])
			}
		}
		a[0] ^= voidRC[r]
	}
}

func sha3256T(data []byte) [32]byte {
	const rate = 136
	var state [25]uint64
	state[16] ^= domainTag ^ uint64(len(data))

	buf := make([]byte, len(data))
	copy(buf, data)
	buf = append(buf, 0x06)
	for len(buf)%rate != 0 {
		buf = append(buf, 0x00)
	}
	buf[len(buf)-1] |= 0x80

	for i := 0; i < len(buf); i += rate {
		for j := 0; j < rate/8; j++ {
			state[j] ^= binary.LittleEndian.Uint64(buf[i+j*8 : i+j*8+8])
		}
		keccakF(&state)
	}

	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:i*8+8], state[i])
	}
	return out
}

const (
	scratchpadSize  = 4 * 1024 * 1024
	scratchpadWords = scratchpadSize / 8
	expandRounds    = scratchpadSize / 64
)

func expandScratchpad(seed [32]byte) []uint64 {
	pad := make([]uint64, scratchpadWords)
	prev := seed[:]
	idx := 0
	ibuf := make([]byte, 4)
	for i := 0; i < expandRounds; i++ {
		binary.LittleEndian.PutUint32(ibuf, uint32(i))
		input := append(prev, seed[:]...)
		input = append(input, ibuf...)
		h := sha3256T(input)
		h2 := sha3256T(append(h[:], ibuf...))
		for j := 0; j < 4 && idx < scratchpadWords; j++ {
			pad[idx] = binary.LittleEndian.Uint64(h[j*8 : j*8+8])
			idx++
		}
		for j := 0; j < 4 && idx < scratchpadWords; j++ {
			pad[idx] = binary.LittleEndian.Uint64(h2[j*8 : j*8+8])
			idx++
		}
		prev = h[:]
	}
	return pad
}

func walkScratchpad(pad []uint64) [32]byte {
	acc := pad[0]
	pos := uint64(0)
	steps := scratchpadWords / 4
	for i := 0; i < steps; i++ {
		pos = (acc ^ pad[pos%uint64(len(pad))]) % uint64(len(pad))
		val := pad[pos]
		acc = bits.RotateLeft64(acc^val, int(pos&63)) ^ uint64(i)
		pad[pos] = acc
	}
	var folded [32]byte
	tail := pad[len(pad)-32:]
	for i, w := range tail {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, w^acc)
		for j := 0; j < 8; j++ {
			folded[(i*8+j)%32] ^= b[j]
		}
	}
	return folded
}

// Hash computes a VoidHash of the given header and nonce.
// header: block header bytes WITHOUT nonce (76 bytes)
// nonce: 64-bit nonce
// Returns 32-byte PoW hash.
func Hash(header []byte, nonce uint64) [32]byte {
	nonceBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBuf, nonce)
	seed := sha3256T(append(header, nonceBuf...))
	pad := expandScratchpad(seed)
	folded := walkScratchpad(pad)
	return sha3256T(append(folded[:], seed[:]...))
}

// MeetsTarget returns true if hash <= target (both 32-byte big-endian integers).
func MeetsTarget(hash [32]byte, target []byte) bool {
	for i := 0; i < 32; i++ {
		if hash[i] < target[i] {
			return true
		}
		if hash[i] > target[i] {
			return false
		}
	}
	return true
}

package gosphincs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

//
// Changing parameters might have some unwanted causes.
// Audit the code first.

type Wots struct {
	//	PkSeed []byte
}

// chain computes `steps` iteration of `F` on an n-byte `input`.
// encoding an `address` and a public seed `pkSeed` in `F`.
// The `input` is either the secret (`offset` 0) or
// an already chained value (`offset` > 0).
func (w *Wots) chain(input []byte, offset, steps uint8, pkSeed []byte, address *Address) []byte {
	if steps == 0 {
		return input
	}
	if (offset + steps) > (WOTSSteps - 1) {
		panic("offset+steps cannot be greater than WOTSSteps-1")
	}

	tmp := w.chain(input, offset, steps-1, pkSeed, address)

	address.HashAddress = uint32(offset + steps - 1)
	tmp = F(pkSeed, address, tmp)
	return tmp
}

// GenSecretKey generates a secret key and return it
func (w *Wots) GenSecretKey(skSeed []byte, address *Address) []byte {
	sk := make([]byte, WOTSLen*SecurityParameter)
	for i := uint32(0); i < WOTSLen; i++ {
		address.ChainAddress = i
		address.HashAddress = 0
		copy(sk[i*SecurityParameter:], Prf(skSeed, address))
	}
	return sk
}

func (w *Wots) GenPublicKey(skSeed, pkSeed []byte, address *Address) []byte {
	wotsPkAddress := address
	sk := make([]byte, WOTSLen*SecurityParameter)
	tmp := make([]byte, WOTSLen*SecurityParameter)
	for i := uint32(0); i < WOTSLen; i++ {
		address.ChainAddress = i
		address.HashAddress = 0
		copy(sk[i*SecurityParameter:], Prf(skSeed, address))
		copy(tmp[i*SecurityParameter:], w.chain(sk[i*SecurityParameter:(i+1)*SecurityParameter], 0, WOTSSteps-1, pkSeed, address))
	}
	wotsPkAddress.Type = WotsPk
	wotsPkAddress.KeyPairAddress = address.KeyPairAddress
	return Tl(pkSeed, wotsPkAddress, tmp)
}

func (w *Wots) Sign(message, skSeed, pkSeed []byte, address *Address) []byte {
	csum := uint32(0)
	// convert message to base w
	chunkedMessage := baseW(message, WOTSChunkSize, WOTSChunks)
	// compute checksum
	for i := uint32(0); i < WOTSChunks; i++ {
		csum = csum + WOTSSteps - 1 - uint32(chunkedMessage[i])
	}
	// shift checksum left if it is not a multiple of bytes
	csum = csum << (8 - ((WOTSChecksumChunks * WOTSChunkSize) % 8))
	// number of bytes that can contain the checksum
	fmt.Println("checksum:", csum)
	csumBytes := toByte(csum, int(WOTSChecksumBytes))
	checksum := baseW(csumBytes, WOTSChunkSize, WOTSChecksumChunks)
	// message to sign = baseW of message + checksum
	msg := append(chunkedMessage, checksum...)
	// sign
	sig := make([]byte, len(msg)*SecurityParameter)
	for idx, msgChunk := range msg {
		address.ChainAddress = uint32(idx)
		address.HashAddress = 0
		sk := Prf(skSeed, address)
		sigI := w.chain(sk, 0, msgChunk, pkSeed, address)
		copy(sig[idx*SecurityParameter:], sigI)
	}
	//
	return sig
}

//
// Helpers
//

// toByte(input=3, length=4) => [0, 0, 0, 3]
func toByte(input uint32, length int) []byte {
	res := make([]byte, length)
	//
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], input)
	//
	if length < 4 {
		fmt.Println("length:", length)
		res = res[4-length:]
	} else if length > 4 {
		res = append(bytes.Repeat([]byte{0}, length-4), res...)
	}
	//
	return res
}

func baseW(input []byte, chunkSize, numChunks uint32) []uint8 {
	res := make([]uint8, numChunks)
	mask := uint8((1 << chunkSize) - 1)  // 0b1111 for w=16
	chunksPerBytes := int(8 / chunkSize) // number of w-value per byte
	// go through every byte
	for i := len(input) - 1; i >= 0; i-- {
		temp := uint8(input[i])
		// for every byte, cut by w-chunk
		for offset := chunksPerBytes - 1; offset >= 0; offset-- {
			res[i*chunksPerBytes+offset] = temp & mask
			temp = temp >> chunkSize
		}
	}
	//
	return res
}

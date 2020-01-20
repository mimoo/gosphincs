package gosphincs

import (
	"fmt"
	"math"
)

const (
	// SecurityParameter (n) is the message length, as well as the length
	// of a private key, public key, or signature element in bytes.
	// It also determines the input and output length of the tweakable
	// hash function used for WOTS+, and WOTS+ signing algorithm.
	SecurityParameter = 16

	// WOTSSteps (w) with larger values result in shorter signatures
	// but slower operations. It has no effect on security.
	// The official parameters: 4, 16, or 256.
	// (e.g. for 4, you can encode 4 different values, so 2 bits)
	WOTSSteps = 16

	// HyperTreeHeight (h)
	HyperTreeHeight = 64
	// HyperTreeLayers (d)
	HyperTreeLayers = 8

	// FORSTree (k)
	FORSTree = 10
	// FORSLeaves (t)
	FORSLeaves = 32768 // 2^15
)

var (
	// WOTSLen ("len" in the spec)
	WOTSLen uint32
	//
	WOTSChunkSize uint32
	// WOTSChunks ...
	WOTSChunks uint32
	// WOTSChecksumChunks ...
	WOTSChecksumChunks uint32
	// WOTSChecksumBytes ...
	WOTSChecksumBytes uint32

	// MessageDigestLength ...
	MessageDigestLength uint32
)

func init() {
	fmt.Println("SecurityParameter (n):", SecurityParameter)

	ChunkSize := math.Log2(WOTSSteps)
	if ChunkSize > 8 {
		panic("chunk size should be <= 8")
	}
	WOTSChunkSize = uint32(ChunkSize)
	WOTSChunks = uint32(math.Ceil(8 * SecurityParameter / ChunkSize))
	fmt.Println("WOTSChunks:", WOTSChunks)

	ChecksumSize := float64(WOTSChunks * (WOTSSteps - 1))
	WOTSChecksumChunks = uint32(math.Floor(math.Log2(ChecksumSize)/ChunkSize)) + 1
	fmt.Println("WOTSChecksumChunks:", WOTSChecksumChunks)

	WOTSLen = WOTSChunks + WOTSChecksumChunks

	tmp := math.Ceil((FORSLeaves*math.Log(FORSLeaves)+7)/8) + math.Floor((HyperTreeHeight-HyperTreeHeight/HyperTreeLayers+7)/8) + math.Floor((HyperTreeHeight/HyperTreeLayers+7)/8)
	MessageDigestLength = uint32(tmp)
	fmt.Println("MessageDigestLength (m):", MessageDigestLength)

	WOTSChecksumBytes = uint32(math.Ceil(float64(WOTSChecksumChunks*WOTSChunkSize) / 8))
	fmt.Println("WOTSChecksumBytes:", WOTSChecksumBytes)
}

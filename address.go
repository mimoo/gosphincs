package gosphincs

import (
	"bytes"
	"encoding/binary"
)

//
// Addresses (ADRS)
// ================
//
// ...

// There are 5 different types of addresses:
const (
	// WotsHash:  hashes in the WOTS+ schemes
	WotsHash uint32 = iota
	// WotsPk:    compression of the WOTS+ public key
	WotsPk
	// Tree:       hashes within the main Merkle tree consturction
	Tree
	// ForsTree:  hashes in the merkle tree in FORS
	ForsTree
	// ForsRoots: compression of the tree roots of FORS
	ForsRoots
)

var (
	endianness = binary.BigEndian
)

// Address (ADRS) is a 32-byte value. To generate one,
// set the relevant fields manually, then call Bytes().
type Address struct {
	// LayerAddress is the height of a tree within the hypertree starting
	// from height 0 for trees on the bottom layer.
	LayerAddress uint32
	// TreeAddress is the position of a tree within a layer of a multi-tree
	// starting with index 0 for the leftmost tree.
	TreeAddress []byte
	// Type indicates the type of address. There are 5 types described at the
	// top of this document.
	Type uint32

	// KeyPairAddress ...
	KeyPairAddress uint32
	// ChainAddress ...
	ChainAddress uint32
	// HashAddress ...
	HashAddress uint32
	// TreeHeight ...
	TreeHeight uint32
	// TreeIndex ...
	TreeIndex uint32
}

// Bytes returns a byte-representation of the address.
func (a *Address) Bytes() []byte {
	output := new(bytes.Buffer)
	// layer + tree address + type
	binary.Write(output, endianness, a.LayerAddress)
	if len(a.TreeAddress) != 3 {
		panic("address: length of tree address should be 3")
	}
	binary.Write(output, endianness, a.TreeAddress)
	if a.Type > 4 {
		panic("address: type cannot be greater than 4")
	}
	binary.Write(output, endianness, a.Type)
	// depending on type
	switch a.Type {
	case 0: // WOTS+ hash address
		binary.Write(output, endianness, a.KeyPairAddress)
		binary.Write(output, endianness, a.ChainAddress)
		binary.Write(output, endianness, a.HashAddress)
	case 1: // WOTS+ public key compression address
		binary.Write(output, endianness, a.KeyPairAddress)
		binary.Write(output, endianness, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	case 2: // hash tree address
		binary.Write(output, endianness, []byte{0, 0, 0, 0})
		binary.Write(output, endianness, a.TreeHeight)
		binary.Write(output, endianness, a.TreeIndex)
	case 3: // FORS tree address
		binary.Write(output, endianness, a.KeyPairAddress)
		binary.Write(output, endianness, a.TreeHeight)
		binary.Write(output, endianness, a.TreeIndex)
	case 4: // FORS tree roots compression address
		binary.Write(output, endianness, a.KeyPairAddress)
		binary.Write(output, endianness, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	return output.Bytes()
}

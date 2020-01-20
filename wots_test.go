package gosphincs

import (
	"fmt"
	"testing"
)

func TestBaseW(t *testing.T) {
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	output := baseW(input, WOTSChunkSize, WOTSChunks)

	expectedOutput := []uint8{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 1, 0}
	for idx, expected := range expectedOutput {
		if expected != output[idx] {
			t.Fatalf("expected: %02x obtained: %02x", expected, output[idx])
		}
	}
}

func TestSign(t *testing.T) {
	w := Wots{}
	message := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	skSeed := message
	pkSeed := message
	address := Address{}
	address.TreeAddress = []byte{1, 2, 3}
	signature := w.Sign(message, skSeed, pkSeed, &address)
	fmt.Printf("% x\n", signature)
}

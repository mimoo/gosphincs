package gosphincs

import "testing"

func TestOutputLength(t *testing.T) {
	temp := []byte{1, 2, 3, 4}
	output := HashMessage(temp, temp, temp, temp)
	if len(output) != int(MessageDigestLength) {
		t.Errorf("some error")
	}
}

package gosphincs

import "golang.org/x/crypto/sha3"

//
//
//

func HashMessage(r, pkSeed, pKRoot, message []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(r)
	shake.Write(pkSeed)
	shake.Write(pKRoot)
	shake.Write(message)
	output := make([]byte, MessageDigestLength)
	shake.Read(output)
	return output
}

func Prf(seed []byte, address *Address) []byte {
	shake := sha3.NewShake256()
	shake.Write(seed)
	shake.Write(address.Bytes())
	output := make([]byte, SecurityParameter)
	shake.Read(output)
	return output
}

func PrfMessage(sKPrf, optRand, message []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(sKPrf)
	shake.Write(optRand)
	shake.Write(message)
	output := make([]byte, SecurityParameter)
	shake.Read(output)
	return output
}

// simple variant

func F(pkSeed []byte, address *Address, message []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(pkSeed)
	shake.Write(address.Bytes())
	shake.Write(message)
	output := make([]byte, SecurityParameter)
	shake.Read(output)
	return output
}

func H(pkSeed []byte, address *Address, message []byte) []byte {
	return F(pkSeed, address, message)
}

func Tl(pkSeed []byte, address *Address, message []byte) []byte {
	return F(pkSeed, address, message)
}

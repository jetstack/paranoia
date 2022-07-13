package checksum

import (
	"encoding/hex"
	"errors"
)

func ParseSHA1(s string) ([20]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [20]byte{}, err
	}
	if len(b) != 20 {
		return [20]byte{}, errors.New("incorrect length for SHA1")
	}
	var o [20]byte
	copy(o[:], b[:20])
	return o, nil
}

func ParseSHA256(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, errors.New("incorrect length for SHA256")
	}
	var o [32]byte
	copy(o[:], b[:32])
	return o, nil
}

func MustParseSHA1(s string) [20]byte {
	o, err := ParseSHA1(s)
	if err != nil {
		panic(err)
	}
	return o
}

func MustParseSHA256(s string) [32]byte {
	o, err := ParseSHA256(s)
	if err != nil {
		panic(err)
	}
	return o
}

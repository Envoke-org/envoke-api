package common

import (
	"encoding/binary"
	// "github.com/whyrusleeping/cbor/go"
	"io"
)

// Int64

func Int64Bytes(x int64) []byte {
	p := make([]byte, 10)
	n := binary.PutVarint(p, x)
	return p[:n]
}

func Int64(p []byte) int64 {
	x, _ := binary.Varint(p)
	return x
}

// Uint16

func Uint16Bytes(x int) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(x))
	return p
}

func Uint16(p []byte) (int, error) {
	if len(p) < 2 {
		return 0, ErrInvalidSize
	}
	x := binary.BigEndian.Uint16(p)
	return int(x), nil
}

func MustUint16(p []byte) int {
	return int(binary.BigEndian.Uint16(p))

}

func ReadUint16(r io.Reader) (int, error) {
	p, err := ReadN(r, 2)
	if err != nil {
		return 0, err
	}
	x := binary.BigEndian.Uint16(p)
	return int(x), nil
}

func MustReadUint16(r io.Reader) int {
	p := MustReadN(r, 2)
	x := binary.BigEndian.Uint16(p)
	return int(x)
}

func WriteUint16(w io.Writer, x int) {
	p := Uint16Bytes(x)
	w.Write(p)
}

// Uint32

func Uint32Bytes(x int) []byte {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, uint32(x))
	return p
}

func Uint32(p []byte) (int, error) {
	if len(p) < 4 {
		return 0, ErrInvalidSize
	}
	x := binary.BigEndian.Uint32(p)
	return int(x), nil
}

func MustUint32(p []byte) int {
	return int(binary.BigEndian.Uint32(p))
}

func ReadUint32(r io.Reader) (int, error) {
	p, err := ReadN(r, 4)
	if err != nil {
		return 0, err
	}
	x := binary.BigEndian.Uint32(p)
	return int(x), nil
}

func MustReadUint32(r io.Reader) int {
	p := MustReadN(r, 4)
	x := binary.BigEndian.Uint32(p)
	return int(x)
}

func WriteUint32(w io.Writer, x int) {
	p := Uint32Bytes(x)
	w.Write(p)
}

// Uint64

func Uint64Bytes(x int) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, uint64(x))
	return p
}

func Uint64(p []byte) (int, error) {
	if len(p) < 8 {
		return 0, ErrInvalidSize
	}
	x := binary.BigEndian.Uint64(p)
	return int(x), nil
}

func MustUint64(p []byte) int {
	return int(binary.BigEndian.Uint64(p))
}

func ReadUint64(r io.Reader) (int, error) {
	p, err := ReadN(r, 8)
	if err != nil {
		return 0, err
	}
	x := binary.BigEndian.Uint64(p)
	return int(x), nil
}

func MustReadUint64(r io.Reader) int {
	p := MustReadN(r, 8)
	x := binary.BigEndian.Uint64(p)
	return int(x)
}

func WriteUint64(w io.Writer, x int) {
	p := Uint64Bytes(x)
	w.Write(p)
}

// VarUint

func VarUintBytes(x int) []byte {
	return VarOctet([]byte{uint8(x)})
}

func VarUint(octet []byte) (int, error) {
	p, err := VarOctetBytes(octet)
	if err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, ErrInvalidSize
	}
	return int(p[0]), nil
}

func VarUintSize(x int) int {
	return len(VarUintBytes(x))
}

func MustVarUint(octet []byte) int {
	x, err := VarUint(octet)
	Check(err)
	return x
}

func ReadVarUint(r io.Reader) (int, error) {
	b, err := Peek(r)
	if err != nil {
		return 0, err
	}
	p, err := ReadN(r, int(b))
	if err != nil {
		return 0, err
	}
	return VarUint(append([]byte{b}, p...))
}

func MustReadVarUint(r io.Reader) int {
	x, err := ReadVarUint(r)
	Check(err)
	return x
}

func WriteVarUint(w io.Writer, x int) {
	p := VarUintBytes(x)
	w.Write(p)
}

// Octet

const MSB = 0x80

func MustReadVarOctet(r io.Reader) []byte {
	octet, err := ReadVarOctet(r)
	Check(err)
	return octet
}

func ReadVarOctet(r io.Reader) (octet []byte, err error) {
	b, err := Peek(r)
	if err != nil {
		return nil, err
	}
	if b > MSB {
		b, err = Peek(r)
		if err != nil {
			return nil, err
		}
	}
	return ReadN(r, int(b))
}

func WriteVarOctet(w io.Writer, p []byte) {
	w.Write(VarOctet(p))
}

func MustVarOctetBytes(octet []byte) []byte {
	p, err := VarOctetBytes(octet)
	Check(err)
	return p
}

func VarOctetBytes(octet []byte) ([]byte, error) {
	if len(octet) == 0 {
		return nil, ErrInvalidSize
	}
	i := int(octet[0])
	if i < MSB {
		if i+1 > len(octet) {
			return nil, ErrInvalidSize
		}
		return octet[1 : i+1], nil
	}
	i -= MSB
	if i >= len(octet) {
		return nil, ErrInvalidSize
	}
	n := int(octet[i])
	if i+n > len(octet) {
		return nil, ErrInvalidSize
	}
	return octet[i : i+n], nil
}

func VarOctet(p []byte) (octet []byte) {
	if n := len(p); n < MSB {
		octet = []byte{uint8(n)}
	} else {
		for i := 1; ; i++ {
			if n < 1<<uint(i*8) {
				octet = []byte{uint8(MSB | uint(i))}
				octet = append(octet, make([]byte, i)...)
				octet[i] = uint8(n)
				break
			}
		}
	}
	octet = append(octet, p...)
	return
}

func VarOctetLength(p []byte) int {
	return len(VarOctet(p))
}

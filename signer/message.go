package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const TimestampTolerance = 5 * time.Second

// BuildCanonicalMessage constructs the deterministic length-prefixed binary
// message that all signers and the gateway must agree on.
//
// Format (big-endian):
//   [2 bytes: ciphersuite ID]
//   [1 byte:  hash_algo length][N bytes: hash_algo string]
//   [4 bytes: doc_hash length] [M bytes: doc_hash raw bytes]
//   [4 bytes: timestamp length][T bytes: RFC3339 timestamp string]
//   [4 bytes: serial length]   [S bytes: serial/UUID string]
func BuildCanonicalMessage(ciphersuiteID uint16, hashAlgo string, docHash []byte, timestamp string, serial string) []byte {
	buf := make([]byte, 0, 256)

	csBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(csBytes, ciphersuiteID)
	buf = append(buf, csBytes...)

	algoBytes := []byte(hashAlgo)
	buf = append(buf, byte(len(algoBytes)))
	buf = append(buf, algoBytes...)

	dhLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dhLen, uint32(len(docHash)))
	buf = append(buf, dhLen...)
	buf = append(buf, docHash...)

	tsBytes := []byte(timestamp)
	tsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tsLen, uint32(len(tsBytes)))
	buf = append(buf, tsLen...)
	buf = append(buf, tsBytes...)

	srBytes := []byte(serial)
	srLen := make([]byte, 4)
	binary.BigEndian.PutUint32(srLen, uint32(len(srBytes)))
	buf = append(buf, srLen...)
	buf = append(buf, srBytes...)

	return buf
}

// ParseTimestampFromCanonical extracts the timestamp string from a canonical message.
func ParseTimestampFromCanonical(msg []byte) (time.Time, error) {
	offset := 0

	if len(msg) < 3 {
		return time.Time{}, fmt.Errorf("message too short")
	}
	offset += 2 // ciphersuite ID

	algoLen := int(msg[offset])
	offset += 1 + algoLen

	if offset+4 > len(msg) {
		return time.Time{}, fmt.Errorf("message too short for doc hash length")
	}
	dhLen := binary.BigEndian.Uint32(msg[offset : offset+4])
	if dhLen > math.MaxInt32 {
		return time.Time{}, fmt.Errorf("doc hash length overflow")
	}
	offset += 4 + int(dhLen)

	if offset+4 > len(msg) {
		return time.Time{}, fmt.Errorf("message too short for timestamp length")
	}
	tsLen := binary.BigEndian.Uint32(msg[offset : offset+4])
	if tsLen > math.MaxInt32 {
		return time.Time{}, fmt.Errorf("timestamp length overflow")
	}
	offset += 4
	if offset+int(tsLen) > len(msg) {
		return time.Time{}, fmt.Errorf("message too short for timestamp data")
	}

	tsStr := string(msg[offset : offset+int(tsLen)])
	return time.Parse(time.RFC3339Nano, tsStr)
}

// ValidateTimestamp checks that the given timestamp is within ±5 seconds of the current UTC time.
func ValidateTimestamp(ts time.Time) error {
	now := time.Now().UTC()
	diff := now.Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > TimestampTolerance {
		return fmt.Errorf("timestamp drift too large: %v (max %v)", diff, TimestampTolerance)
	}
	return nil
}

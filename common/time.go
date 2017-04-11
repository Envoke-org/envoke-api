package common

import (
	"encoding/binary"
	"time"
)

const shortForm = "2006-01-02"

func Now() time.Time {
	return time.Now().Local()
}

func ParseDate(date string) (time.Time, error) {
	return time.Parse(shortForm, date)
}

func SleepMilli(d time.Duration) {
	time.Sleep(d * time.Millisecond)
}

func SleepSeconds(d time.Duration) {
	time.Sleep(d * time.Second)
}

func Timestamp() int64 {
	return Now().Unix()
}

func TimestampBytes(x int64) []byte {
	p := make([]byte, 10)
	n := binary.PutVarint(p, x)
	return p[:n]
}

func TimestampFromBytes(p []byte) int64 {
	x, _ := binary.Varint(p)
	return x
}

func Today() time.Time {
	now := Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

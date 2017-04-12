package common

import "time"

const shortForm = "2006-01-02"

func Date(day int, month time.Month, year int, location *time.Location) time.Time {
	if location == nil {
		location = time.UTC
	}
	return time.Date(year, month, day, 0, 0, 0, 0, location)
}

func Now() time.Time {
	return time.Now().Local()
}

func ParseDate(datestr string) (time.Time, error) {
	return time.Parse(shortForm, datestr)
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

func Today() time.Time {
	now := Now()
	return Date(now.Day(), now.Month(), now.Year(), now.Location())
}

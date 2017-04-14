package common

import "time"

const shortForm = "2006-01-02"

var NilTime = time.Time{}

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

func ParseTimestamp(timestamp string) (time.Time, error) {
	x, err := ParseFloat64(string(timestamp))
	if err != nil {
		return time.Time{}, err
	}
	sec := int64(x)
	nsec := int64((x - float64(sec)) * float64(1000000))
	return time.Unix(sec, nsec), nil
}

func MustParseTimestamp(timestamp string) time.Time {
	t, err := ParseTimestamp(timestamp)
	Check(err)
	return t
}

func SleepMilli(d time.Duration) {
	time.Sleep(d * time.Millisecond)
}

func SleepSeconds(d time.Duration) {
	time.Sleep(d * time.Second)
}

func Timestamp(t time.Time) string {
	return Sprintf("%.6f", float64(t.UnixNano())/float64(time.Second))
}

func TimestampNow() string {
	return Timestamp(Now())
}

func Today() time.Time {
	now := Now()
	return Date(now.Day(), now.Month(), now.Year(), now.Location())
}

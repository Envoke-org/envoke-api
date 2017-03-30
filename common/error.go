package common

import "github.com/pkg/errors"

var (
	ErrExpectedGet        = Error("Expected GET request")
	ErrExpectedPost       = Error("Expected POST request")
	ErrInvalidCondition   = Error("Invalid condition")
	ErrInvalidFulfillment = Error("Invalid fulfillment")
	ErrInvalidId          = Error("Invalid id")
	ErrInvalidKey         = Error("Invalid key")
	ErrInvalidSignature   = Error("Invalid signature")
	ErrInvalidSize        = Error("Invalid size")
	ErrInvalidType        = Error("Invalid type")
)

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func Error(msg string) error {
	return errors.New(msg)
}

func Errorf(format string, args ...interface{}) error {
	return errors.Errorf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	panic(Sprintf(format, args...))
}

func ErrorAppend(err error, msg string) error {
	return Error(err.Error() + ": " + msg)
}

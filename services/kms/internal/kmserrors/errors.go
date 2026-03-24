package kmserrors

import "errors"

var (
	ErrNotFound        = errors.New("not found")
	ErrNotRotatable    = errors.New("not rotatable")
	ErrInvalidArgument = errors.New("invalid argument")
)

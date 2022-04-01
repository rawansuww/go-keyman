package types

import "fmt"

type ErrorCode int

type InternalError struct {
	ErrorCode    ErrorCode
	ErrorMessage string
	ErrorDetails error
}

func (e *InternalError) Error() string {
	return fmt.Errorf("%s: %w", e.ErrorMessage, e.ErrorDetails).Error()
}

package config

import "fmt"

type OtherServerError struct {
	Entered  string
	Reported string
}

func (e *OtherServerError) Error() string {
	return fmt.Sprintf("the server at %s reports %s as its address", e.Entered, e.Reported)
}

package openssh

import "regexp"

var connectionHashPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

package openssh

import (
	"fmt"
	"os"
	"strings"
)

const sshFlagsNoArgs = "46AaCfGgKkMNnqsTtVvXxYy"

func parseSSHCommand(args []string) (string, string, string, error) {
	host := ""
	port := ""
	user := ""

	lastArg := ""
	for _, arg := range args {
		if arg == "--" {
			break
		}

		if len(arg) < 1 {
			continue
		}

		if arg[0] == '-' {
			lastArg = arg
			continue
		}

		if user == "" && lastArg == "-l" {
			user = arg
			lastArg = arg
			continue
		}

		if port == "" && lastArg == "-p" {
			port = arg
			lastArg = arg
			continue
		}

		if (len(lastArg) > 1 && lastArg[0] == '-' && strings.Contains(sshFlagsNoArgs, string(lastArg[1]))) || // last arg was a flag, arg is our connection string now.
			(lastArg == "" || lastArg[0] != '-') { // arg is the first argument or last arg was a value to a flag, arg is our connection string.

			if host != "" {
				break // we already got the destination, arg is part of the command sent to the server
			}

			// parse connection string

			// port
			if strings.HasPrefix(arg, "ssh://") {
				arg = arg[6:] // remove prefix

				// extract port, this is only valid with ssh:// prefix
				idx := strings.LastIndex(arg, ":")

				p := ""
				if idx >= 0 {
					p = arg[idx+1:]
					arg = arg[:idx]
				}

				if port == "" {
					port = p
				}

			}

			// user
			idx := strings.LastIndex(arg, "@")

			u := ""
			if idx >= 0 {
				u = arg[:idx]
				arg = arg[idx+1:]
			}

			if user == "" {
				user = u
			}

			host = arg // only our host remains
		}

		lastArg = arg
	}

	if port == "" {
		port = "22"
	}

	if user == "" {
		user = os.Getenv("USER")
	}

	if user == "" {
		user = os.Getenv("USERNAME")
	}

	if user == "" {
		return "", "", "", fmt.Errorf("user not specified")
	}

	if host == "" {
		return "", "", "", fmt.Errorf("host not specified")
	}

	return user, host, port, nil
}

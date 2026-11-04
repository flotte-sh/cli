package winscp

import "strings"

func winSCPCommandLine(arguments []string) string {
	var command strings.Builder
	for index, argument := range arguments {
		if index != 0 {
			command.WriteByte(' ')
		}
		command.WriteByte('"')
		for _, character := range argument {
			if character == '"' {
				command.WriteByte('"')
			}
			command.WriteRune(character)
		}
		command.WriteByte('"')
	}
	return command.String()
}

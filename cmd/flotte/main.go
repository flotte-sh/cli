package main

import (
	"os"
	"runtime/debug"

	"github.com/flotte-sh/flotte-cli/internal/commands"
)

// normal flow:
// 1. download the login data from the flotte server, this contains the client id, realm, auth server url, this is saved in $Home/.flotte/config.json
// go run cmd/cli/main.go bootstrap http://localhost:3000

// var nFlag = flag.Int("n", 1234, "help message for flag n")
// fmt.Printf("test %d\n", *nFlag)
// conf := config.NewConfig()
//
// ts := auth.ExecuteDeviceFlow()
//
// result, err := client.GetCertificate(conf, ts)
// if err != nil {
// 	fmt.Printf("Error fetching user keys: %v\n", err)
// 	return
// }
//
// // Print the result
// fmt.Printf("User keys: %v\n", result)

var version = "dev"

func main() {
	// Attempt to read version from build info (if injected via -ldflags)
	if info, ok := debug.ReadBuildInfo(); ok && version == "dev" {
		if info.Main.Version != "(devel)" && info.Main.Version != "" {
			version = info.Main.Version
		}
	}

	if os.Getenv("FLOTTE_INVOKED_SSH") == "1" {
		// the user already ran "flotte ssh ..." but he also has his ssh config configured to run flotte. just exit here.
		os.Exit(1)
	}

	commands.Execute(version)
}

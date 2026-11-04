//go:build windows

package pageant

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os/user"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const pageantPipePrefix = `\\.\pipe\pageant.`

func Listen() (listener net.Listener, pipePath string, err error) {
	pipePath, err = CurrentUserPipePath()
	if err != nil {
		return nil, "", err
	}
	listener, err = ListenPipe(pipePath)
	if err != nil {
		return nil, "", err
	}
	return listener, pipePath, nil
}

func ListenPipe(pipePath string) (net.Listener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("identify Pageant pipe owner: %w", err)
	}
	sid := user.User.Sid.String()
	return winio.ListenPipe(pipePath, &winio.PipeConfig{
		SecurityDescriptor: "O:" + sid + "D:P(A;;GA;;;" + sid + ")",
	})
}

func CurrentUserPipePath() (string, error) {
	username, err := currentUsername()
	if err != nil {
		return "", err
	}
	return PipePath(username)
}

func PipePath(username string) (string, error) {
	digest, err := pageantPipeDigest()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s.%x", pageantPipePrefix, username, digest), nil
}

func pageantPipeDigest() ([sha256.Size]byte, error) {
	var encoded [20]byte
	binary.BigEndian.PutUint32(encoded[:4], 16)
	copy(encoded[4:], "Pageant")
	protect := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptProtectMemory")
	if err := protect.Find(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("find Windows memory protection API: %w", err)
	}
	ok, _, callErr := protect.Call(uintptr(unsafe.Pointer(&encoded[4])), 16, 1) // #nosec G103 -- The API receives exactly the 16-byte block after the four-byte SSH length prefix.
	if ok == 0 {
		return [sha256.Size]byte{}, fmt.Errorf("protect Pageant pipe name: %w", callErr)
	}
	return sha256.Sum256(encoded[:]), nil
}

func currentUsername() (string, error) {
	if err := windows.NewLazySystemDLL("sspicli.dll").Load(); err == nil {
		var size uint32
		if err := windows.GetUserNameEx(windows.NameUserPrincipal, nil, &size); err == windows.ERROR_MORE_DATA && size > 0 {
			buffer := make([]uint16, size)
			if err := windows.GetUserNameEx(windows.NameUserPrincipal, &buffer[0], &size); err == nil {
				username := windows.UTF16ToString(buffer)
				if at := strings.IndexByte(username, '@'); at >= 0 {
					username = username[:at]
				}
				if username != "" {
					return username, nil
				}
			}
		}
	}
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get Pageant username: %w", err)
	}
	username := current.Username
	if slash := strings.LastIndexByte(username, '\\'); slash >= 0 {
		username = username[slash+1:]
	}
	if username == "" {
		return "", fmt.Errorf("the Windows Pageant username is empty")
	}
	return username, nil
}

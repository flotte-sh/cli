package winscp

import (
	"io"
	"sync"
)

type synchronizedWriter struct {
	io.Writer
	mutex *sync.Mutex
}

func (writer synchronizedWriter) Write(data []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return writer.Writer.Write(data)
}

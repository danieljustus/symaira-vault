package diff

import "bytes"

const maxCapturedStreamBytes = 16 << 20

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func newLimitedBuffer() *limitedBuffer {
	return &limitedBuffer{remaining: maxCapturedStreamBytes}
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if len(value) > buffer.remaining {
		value = value[:buffer.remaining]
		buffer.truncated = true
	}
	if len(value) > 0 {
		_, _ = buffer.buffer.Write(value)
		buffer.remaining -= len(value)
	}
	if buffer.remaining == 0 && originalLength > len(value) {
		buffer.truncated = true
	}
	return originalLength, nil
}

func (buffer *limitedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *limitedBuffer) Truncated() bool {
	return buffer.truncated
}

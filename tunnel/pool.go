package tunnel

import (
	"sync"

	"github.com/Blocked233/middleware/proto"
)

type byteReuse struct {
	buf []byte
}

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return &byteReuse{buf: make([]byte, 1500)}
		},
	}

	tunBytesPool = sync.Pool{
		New: func() interface{} {
			return &proto.TunByte{}
		},
	}
)

package tunnel

import (
	"sync"

	"github.com/panjf2000/ants/v2"
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
	webPool *ants.PoolWithFunc
)

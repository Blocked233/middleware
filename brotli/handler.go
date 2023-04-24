package brotli

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
)

type brotliHandler struct {
	*Options
	brPool sync.Pool
}

func newBrotliHandler(level int, options ...Option) *brotliHandler {
	handler := &brotliHandler{
		Options: DefaultOptions,
		brPool: sync.Pool{
			New: func() interface{} {
				br := brotli.NewWriterLevel(io.Discard, level)
				return br
			},
		},
	}
	for _, setter := range options {
		setter(handler.Options)
	}
	return handler
}

func (b *brotliHandler) Handle(c *gin.Context) {
	if fn := b.DecompressFn; fn != nil && c.Request.Header.Get("Content-Encoding") == "br" {
		fn(c)
	}

	if !b.shouldCompress(c.Request) {
		return
	}

	br := b.brPool.Get().(*brotli.Writer)
	defer b.brPool.Put(br)
	defer br.Reset(io.Discard)
	br.Reset(c.Writer)

	c.Header("Content-Encoding", "br")
	c.Header("Vary", "Accept-Encoding")
	c.Writer = &brotliWriter{c.Writer, br}
	defer func() {
		br.Close()
		c.Header("Content-Length", fmt.Sprint(c.Writer.Size()))
	}()
	c.Next()
}

func (b *brotliHandler) shouldCompress(req *http.Request) bool {

	if !strings.Contains(req.Header.Get("Accept-Encoding"), "br") ||
		strings.Contains(req.Header.Get("Connection"), "Upgrade") ||
		strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		return false
	}

	extension := filepath.Ext(req.URL.Path)
	if b.ExcludedExtensions.Contains(extension) {
		return false
	}

	if b.ExcludedPaths.Contains(req.URL.Path) {
		return false
	}
	if b.ExcludedPathesRegexs.Contains(req.URL.Path) {
		return false
	}

	return true
}

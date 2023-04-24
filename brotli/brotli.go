package middleware

import (
	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
)

const (
	BestCompression    = brotli.BestCompression
	BestSpeed          = brotli.BestSpeed
	DefaultCompression = brotli.DefaultCompression
)

func Brotli(level int, options ...Option) gin.HandlerFunc {
	return newBrotliHandler(level, options...).Handle
}

type brotliWriter struct {
	gin.ResponseWriter
	writer *brotli.Writer
}

func (b *brotliWriter) WriteString(s string) (int, error) {
	b.Header().Del("Content-Length")
	return b.writer.Write([]byte(s))
}

func (b *brotliWriter) Write(data []byte) (int, error) {
	b.Header().Del("Content-Length")
	return b.writer.Write(data)
}

func (b *brotliWriter) WriteHeader(code int) {
	b.Header().Del("Content-Length")
	b.ResponseWriter.WriteHeader(code)
}

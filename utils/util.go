package utils

import "io"

func Exchange(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

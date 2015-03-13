// +build freebsd

/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>
*/

package govpn

import (
	"io"
	"os"
	"path"
)

func newTAPer(ifaceName string) (io.ReadWriter, error) {
	return os.OpenFile(path.Join("/dev/", ifaceName), os.O_RDWR, os.ModePerm)
}

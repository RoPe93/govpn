// +build freebsd

/*
govpn -- Simple secure virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>
*/

package main

import (
	"os"
	"path"
)

func NewTAP(ifaceName string) TAP {
	fd, err := os.OpenFile(path.Join("/dev/", ifaceName), os.O_RDWR, os.ModePerm)
	if err != nil {
		panic(err)
	}
	return fd
}

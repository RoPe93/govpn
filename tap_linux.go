// +build linux

/*
govpn -- Simple secure virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>
*/

package main

import (
	"github.com/chon219/water"
)

func NewTAP(string ifaceName) TAP {
	iface, err := water.NewTAP(ifaceName)
	if err != nil {
		panic(err)
	}
	return iface
}

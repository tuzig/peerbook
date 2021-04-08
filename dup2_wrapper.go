// +build !arm freebsd
// +build !arm,!arm64 !linux

package main

import "syscall"

//Dup2 is the system dup2 for systems that are lacking it
func Dup2(oldfd int, newfd int) {
	syscall.Dup2(oldfd, newfd)
}

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"syscall"
)

func main() {
	terminate, err := Boot()
	if err != nil {
		log.Fatal(err)
	}
	defer terminate()
	Main()
}

func Main() {
	showmounts()
	if err := mount("/tmp/hello", 4*1024); err != nil {
		log.Fatal(err)
	}
	defer syscall.Unmount("/tmp/hello", 0)
	showmounts()
}

func mount(path string, size int64) error {
	os.MkdirAll(path, 0755)
	var flags uintptr
	flags = syscall.MS_NOATIME | syscall.MS_SILENT
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := ""
	if size >= 0 {
		options = "size=" + strconv.FormatInt(size, 10)
	}

	fmt.Println("Mounting tmpfs to", path)
	return syscall.Mount("tmpfs", path, "tmpfs", flags, options)
}

func showmounts() {
	b, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}

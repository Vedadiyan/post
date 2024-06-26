//go:build !linux
// +build !linux

package post

func setSocketMark(fd int, value int) (e error) {
	return nil
}

func setSocketInterface(fd int, value string) (e error) {
	return nil
}

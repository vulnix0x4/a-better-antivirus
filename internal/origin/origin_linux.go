package origin

import "golang.org/x/sys/unix"

// Of reads the download address Chromium-based browsers, curl --xattr and
// wget --xattr store on a file (where the file system keeps user attributes).
func Of(path string) *Origin {
	o := &Origin{File: path, URL: xattr(path, "user.xdg.origin.url"), Referrer: xattr(path, "user.xdg.referrer.url")}
	if !useful(o.URL) && !useful(o.Referrer) {
		return nil
	}
	return o
}

func xattr(path, name string) string {
	b := make([]byte, 4<<10)
	n, err := unix.Getxattr(path, name, b)
	if err != nil || n <= 0 {
		return ""
	}
	return clean(string(b[:n]))
}

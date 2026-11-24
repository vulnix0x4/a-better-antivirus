package autopsy

// What's inside an archive a stealer made: stealers zip up what they
// collected before they upload it, so the list of names in it is the list of
// what it took (or was about to). Each name is checked against the baits and
// the real stores: by its contents where the archive says what they are
// (a zip keeps a checksum of every file), by its name otherwise.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
)

// maxEntries is how many names of one archive are listed.
const maxEntries = 500

// archiveKind says what kind of archive a file is, from its first bytes
// ("" if none ABA can read; "7z" and "rar" are recognised but not read).
func archiveKind(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return "zip"
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "tar.gz"
	case bytes.HasPrefix(head, []byte("7z\xbc\xaf\x27\x1c")):
		return "7z"
	case bytes.HasPrefix(head, []byte("Rar!\x1a\x07")):
		return "rar"
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// known is what an archive's entries (and loose staged files) are checked
// against: the baits and the real stores' files.
type known struct {
	baits  []knownFile
	reals  []knownFile
	stores []baits.Store
}

type knownFile struct {
	path, what string
	size       int64
	crc        uint32
	crcDone    bool
	crcOK      bool
}

func newKnown(baitFiles map[string]string, stores []baits.Store, realFiles map[string]string) *known {
	k := &known{stores: stores}
	for p, name := range baitFiles {
		if fi, err := os.Stat(p); err == nil {
			k.baits = append(k.baits, knownFile{path: p, what: name, size: fi.Size()})
		}
	}
	for p, name := range realFiles {
		if fi, err := os.Stat(p); err == nil {
			k.reals = append(k.reals, knownFile{path: p, what: name, size: fi.Size()})
		}
	}
	return k
}

// crcOf reads a file to checksum it, at most once. A real store's file is
// read only here, only to compare it with a copy found in what the program
// staged, and nothing of it is kept.
func (f *knownFile) crcOf() (uint32, bool) {
	if f.crcDone {
		return f.crc, f.crcOK
	}
	f.crcDone = true
	fh, err := os.Open(f.path)
	if err != nil {
		return 0, false
	}
	defer fh.Close()
	h := crc32.NewIEEE()
	if _, err := io.Copy(h, io.LimitReader(fh, 1<<30)); err != nil {
		return 0, false
	}
	f.crc, f.crcOK = h.Sum32(), true
	return f.crc, true
}

// tailMatch: name ends with the last two parts of p ("Default/Login Data"),
// or the last one when that's all name has.
func tailMatch(name, p string) bool {
	n := strings.Split(strings.Trim(strings.ReplaceAll(name, `\`, "/"), "/"), "/")
	q := strings.Split(filepath.ToSlash(p), "/")
	k := 2
	if len(n) < k {
		k = len(n)
	}
	if len(q) < k || k == 0 {
		return false
	}
	for i := 1; i <= k; i++ {
		// Archive names come from any system: compared without case.
		if !strings.EqualFold(n[len(n)-i], q[len(q)-i]) {
			return false
		}
	}
	return true
}

// Verdicts on a staged file or archive entry.
const (
	isBait     = "bait"
	isReal     = "real" // the same bytes as a real store's file now
	likeReal   = "like-real"
	likeBait   = "like-bait"
	notKnown   = ""
	realPrefix = "your real "
)

// classify says what a file named name (of size bytes, whose checksum crc
// gives if it can) is: a bait, a copy of a real store's file, or named like
// one.
func (k *known) classify(name string, size int64, crc func() (uint32, bool)) (verdict, what string) {
	sum, haveSum := uint32(0), false
	sumOnce := false
	getSum := func() (uint32, bool) {
		if !sumOnce {
			sumOnce = true
			if crc != nil {
				sum, haveSum = crc()
			}
		}
		return sum, haveSum
	}
	for i := range k.baits {
		b := &k.baits[i]
		if b.size != size {
			continue
		}
		if s, ok := getSum(); ok {
			if bs, ok := b.crcOf(); ok && bs == s {
				return isBait, "a bait (" + b.what + "): fake, nothing lost"
			}
		}
	}
	for i := range k.reals {
		r := &k.reals[i]
		if r.size != size {
			continue
		}
		if s, ok := getSum(); ok {
			if rs, ok := r.crcOf(); ok && rs == s {
				return isReal, r.what + ": the same bytes as your real file " + r.path
			}
		}
	}
	for _, b := range k.baits {
		if tailMatch(name, b.path) {
			return likeBait, "named like a bait (" + b.what + ")"
		}
	}
	for _, r := range k.reals {
		if tailMatch(name, r.path) {
			return likeReal, "named like " + r.what + "'s file " + filepath.Base(r.path) + " (its contents don't match that file as it is now; it may have changed since)"
		}
	}
	for _, s := range k.stores {
		for _, f := range s.Files {
			if g := path.Base(f); !strings.ContainsAny(g, "*?[") && strings.EqualFold(path.Base(strings.ReplaceAll(name, `\`, "/")), g) {
				return likeReal, "named like a file of " + s.Name
			}
		}
	}
	return notKnown, ""
}

// listArchive lists what's in the archive at p (of kind), classifying each
// entry. More is how many weren't listed.
func (k *known) listArchive(p, kind string) (entries []alerts.ArchiveEntry, more int, err error) {
	add := func(name string, size int64, crc func() (uint32, bool)) {
		if len(entries) >= maxEntries {
			more++
			return
		}
		_, what := k.classify(name, size, crc)
		entries = append(entries, alerts.ArchiveEntry{Name: name, Size: size, What: what})
	}
	switch kind {
	case "zip":
		zr, err := zip.OpenReader(p)
		if err != nil {
			return nil, 0, err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			f := f
			add(f.Name, int64(f.UncompressedSize64), func() (uint32, bool) { return f.CRC32, true })
		}
		return entries, more, nil
	case "tar", "tar.gz":
		fh, err := os.Open(p)
		if err != nil {
			return nil, 0, err
		}
		defer fh.Close()
		var r io.Reader = bufio.NewReader(fh)
		if kind == "tar.gz" {
			gz, err := gzip.NewReader(r)
			if err != nil {
				return nil, 0, err
			}
			defer gz.Close()
			r = gz
		}
		tr := tar.NewReader(r)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return entries, more, nil
			}
			if err != nil {
				return entries, more, err
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
				continue
			}
			// A tar keeps no checksums: the entry is read (it's next in the
			// stream anyway) when its size is one worth comparing.
			size := h.Size
			add(h.Name, size, func() (uint32, bool) {
				if !k.sizeKnown(size) {
					return 0, false
				}
				c := crc32.NewIEEE()
				if _, err := io.Copy(c, io.LimitReader(tr, 1<<30)); err != nil {
					return 0, false
				}
				return c.Sum32(), true
			})
		}
	}
	return nil, 0, nil
}

func (k *known) sizeKnown(n int64) bool {
	for _, f := range k.baits {
		if f.size == n {
			return true
		}
	}
	for _, f := range k.reals {
		if f.size == n {
			return true
		}
	}
	return false
}

// fileCRC checksums a loose file (at most 1 GB of it).
func fileCRC(p string) (uint32, bool) {
	f, err := os.Open(p)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	h := crc32.NewIEEE()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return 0, false
	}
	return h.Sum32(), true
}

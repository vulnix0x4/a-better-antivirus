// Command build compiles ABA-Setup.exe from installer/aba.iss with Inno Setup.
//
// In a release, GoReleaser runs it once for each aba.exe it has just built:
//
//	go run ./installer/build -arch amd64 -bin dist/.../aba.exe -version v1.2.3
//
// Each call sets its binary aside in dist/installer/bin. The call that brings
// the second one compiles the installer from the two. That way the aba.exe
// files inside ABA-Setup.exe are the very files GoReleaser publishes as
// aba_<version>_windows_<arch>.exe, not a second build of the same source.
//
// To look at the wizard without being able to install anything:
//
//	go run ./installer/build -preview
//
// The Inno Setup compiler is found through the ISCC environment variable (the
// path of ISCC.exe; installer/get-inno.ps1 sets it up), then on PATH.
package main

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Machine types in a Windows program's header.
var machines = map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64}

func main() {
	arch := flag.String("arch", "", "architecture of -bin: amd64 or arm64")
	bin := flag.String("bin", "", "an aba.exe that was just built")
	version := flag.String("version", "", "version of the aba.exe files, like v1.2.3")
	out := flag.String("out", filepath.Join("dist", "installer"), "folder for ABA-Setup.exe (the binaries are kept in its bin subfolder)")
	script := flag.String("script", filepath.Join("installer", "aba.iss"), "the Inno Setup script")
	preview := flag.Bool("preview", false, "build ABA-Setup-preview.exe: the wizard only, with no aba.exe inside")
	flag.Parse()

	if err := run(*arch, *bin, *version, *out, *script, *preview); err != nil {
		fmt.Fprintln(os.Stderr, "installer:", err)
		os.Exit(1)
	}
}

func run(arch, bin, version, out, script string, preview bool) error {
	out, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if preview {
		if version == "" {
			version = "v0.0.0"
		}
		return compile(script, out, "", version, true)
	}
	if _, ok := machines[arch]; !ok || bin == "" || version == "" {
		return errors.New("need -arch amd64|arm64, -bin <aba.exe> and -version <vX.Y.Z> (or -preview)")
	}

	// GoReleaser builds both architectures at the same time, so two of these
	// can run at once. One at a time from here on.
	unlock, err := lock(filepath.Join(out, ".lock"))
	if err != nil {
		return err
	}
	defer unlock()

	binDir := filepath.Join(out, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if err := stage(bin, staged(binDir, arch), arch); err != nil {
		return err
	}
	for a := range machines {
		if _, err := os.Stat(staged(binDir, a)); err != nil {
			fmt.Printf("installer: kept the %s aba.exe; waiting for %s\n", arch, a)
			return nil
		}
	}
	if err := compile(script, out, binDir, version, false); err != nil {
		return err
	}
	// For the build log: what went in, and what came out.
	for _, f := range []string{staged(binDir, "amd64"), staged(binDir, "arm64"), filepath.Join(out, "ABA-Setup.exe")} {
		sum, err := sha256File(f)
		if err != nil {
			return err
		}
		fmt.Printf("installer: %s  %s\n", sum, filepath.Base(f))
	}
	return nil
}

func staged(binDir, arch string) string { return filepath.Join(binDir, "aba-"+arch+".exe") }

// stage copies a finished aba.exe next to the other one, after checking it
// really is a Windows program for the processor it claims: a mix-up here
// would install a program that can't start.
func stage(src, dst, arch string) error {
	f, err := pe.Open(src)
	if err != nil {
		return fmt.Errorf("%s is not a Windows program: %w", src, err)
	}
	machine := f.Machine
	f.Close()
	if machine != machines[arch] {
		return fmt.Errorf("%s is not built for %s (machine type 0x%04x)", src, arch, machine)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".part"
	o, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, in); err != nil {
		o.Close()
		return err
	}
	if err := o.Close(); err != nil {
		return err
	}
	// Only a complete file ever has the final name.
	return os.Rename(tmp, dst)
}

var releaseVersion = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)`)

func compile(script, out, binDir, version string, preview bool) error {
	iscc, err := findISCC()
	if err != nil {
		return err
	}
	// The setup file's properties want plain numbers.
	numeric := "0.0.0"
	if m := releaseVersion.FindStringSubmatch(version); m != nil {
		numeric = m[1] + "." + m[2] + "." + m[3]
	}
	if strings.ContainsAny(version, "\" \t") {
		return fmt.Errorf("odd version %q", version)
	}
	name := "ABA-Setup.exe"
	args := []string{"/Qp", "/DAppVersion=" + version, "/DAppVersionNumeric=" + numeric, "/DOutDir=" + out}
	if preview {
		name = "ABA-Setup-preview.exe"
		args = append(args, "/DPreview")
	} else {
		args = append(args, "/DBinDir="+binDir)
	}
	target := filepath.Join(out, name)
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cmd := exec.Command(iscc, append(args, script)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the Inno Setup compiler (%s) failed: %w", iscc, err)
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("the Inno Setup compiler reported success but %s is missing", target)
	}
	fmt.Println("installer: built", target)
	return nil
}

func findISCC() (string, error) {
	if p := os.Getenv("ISCC"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("ISCC is set to %s, which doesn't exist", p)
		}
		return p, nil
	}
	if p, err := exec.LookPath("ISCC.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("the Inno Setup compiler wasn't found. Run installer/get-inno.ps1 and set ISCC to the path it prints")
}

// lock makes dir, which only one process can do, and waits its turn if
// another has it. The returned function gives it back.
func lock(dir string) (func(), error) {
	deadline := time.Now().Add(10 * time.Minute)
	for {
		err := os.Mkdir(dir, 0o755)
		if err == nil {
			return func() { os.Remove(dir) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s has been there for 10 minutes: delete it if no build is running", dir)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

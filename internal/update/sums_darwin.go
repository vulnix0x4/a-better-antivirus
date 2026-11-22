package update

// sumsName is the signed checksum list of the files for this system. The
// macOS files have a list of their own, next to SHA256SUMS.txt: that one is
// the Windows files' list, and promises to hold nothing else
// (installer/verify.ps1).
const sumsName = "SHA256SUMS-macos.txt"

package winsec

// The flight recorder's audit rules (see package recorder): on the folders
// that hold your real browser profiles, wallets and keys, an audit rule that
// every file directly in the folder inherits. A rule on each file would be
// lost whenever an app replaces the file with a new one (browsers do that
// to "Local State", Firefox to logins.json, LevelDB to its files all the
// time); an inherited one is on every new file from the moment it's made.
//
// It's kept as small as it can be:
//
//   - Only "read data", only successes: a program changing or listing a
//     file isn't logged.
//   - Only the files directly in that folder (NO_PROPAGATE): never the
//     cache folders below a profile, where a browser works all day.
//   - Never the folder itself (INHERIT_ONLY), never other rules: it's added
//     to whatever audit rules the folder has, and removing it takes only it.
//
// It's recognised as ABA's by its exact shape (that mask, those flags,
// Everyone), so uninstalling removes exactly what ABA added.

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RecorderAuditMask is what the recorder audits: reading a file's data.
const RecorderAuditMask = fileReadData

const recorderInherit = windows.OBJECT_INHERIT_ACE | windows.NO_PROPAGATE_INHERIT_ACE | windows.INHERIT_ONLY_ACE

const (
	systemAuditAceType      = 2
	successfulAccessAceFlag = 0x40
)

var procDeleteAce = advapi.NewProc("DeleteAce")

func folderSACL(dir string) (*windows.ACL, *windows.SECURITY_DESCRIPTOR, error) {
	if err := EnablePrivilege(SeSecurityPrivilege); err != nil {
		return nil, nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return nil, sd, nil // no SACL at all
		}
		return nil, sd, nil
	}
	return sacl, sd, nil
}

// recorderACEs lists the indexes of ABA's recorder rules in acl.
func recorderACEs(acl *windows.ACL) []uint32 {
	if acl == nil {
		return nil
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return nil
	}
	var out []uint32
	n := aclAceCount(acl)
	for i := uint32(0); i < n; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			continue
		}
		if ace.Header.AceType != systemAuditAceType || uint32(ace.Mask) != RecorderAuditMask {
			continue
		}
		flags := ace.Header.AceFlags
		if flags&recorderInherit != recorderInherit || flags&successfulAccessAceFlag == 0 || flags&windows.INHERITED_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(everyone) {
			out = append(out, i)
		}
	}
	return out
}

// HasRecorderAudit reports whether ABA's recorder rule is on dir.
func HasRecorderAudit(dir string) (bool, error) {
	sacl, _, err := folderSACL(dir)
	if err != nil {
		return false, err
	}
	return len(recorderACEs(sacl)) > 0, nil
}

// SetRecorderAudit adds ABA's recorder rule to dir (if it isn't there),
// keeping any audit rules the folder has. Windows passes it on to the files
// directly in the folder, the ones there now and every new one.
func SetRecorderAudit(dir string) error {
	sacl, _, err := folderSACL(dir)
	if err != nil {
		return err
	}
	if len(recorderACEs(sacl)) > 0 {
		return nil
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: RecorderAuditMask,
		AccessMode:        windows.SET_AUDIT_SUCCESS,
		Inheritance:       recorderInherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, sacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION, nil, nil, nil, acl)
}

// ClearRecorderAudit removes ABA's recorder rule from dir (and so from the
// files in it), and nothing else.
func ClearRecorderAudit(dir string) error {
	sacl, _, err := folderSACL(dir)
	if err != nil {
		return err
	}
	idx := recorderACEs(sacl)
	if len(idx) == 0 {
		return nil
	}
	size := *(*uint16)(unsafe.Add(unsafe.Pointer(sacl), 2))
	buf := make([]uint64, (int(size)+7)/8)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), int(size)), unsafe.Slice((*byte)(unsafe.Pointer(sacl)), int(size)))
	acl := (*windows.ACL)(unsafe.Pointer(&buf[0]))
	for i := len(idx) - 1; i >= 0; i-- {
		if r, _, e := procDeleteAce.Call(uintptr(unsafe.Pointer(acl)), uintptr(idx[i])); r == 0 {
			return e
		}
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION, nil, nil, nil, acl)
}

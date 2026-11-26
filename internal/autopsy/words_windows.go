package autopsy

const pcWord = "PC"

// limits is what the flight recorder can't see on Windows, said after "no sign".
const limits = "ABA sees a file being opened through Windows' own file auditing. A program that reads the disk underneath the file system, reads a shadow copy, or has your browser hand it the data (through its debugging port, or code injected into it) doesn't show up as opening the file, and connections it had already closed aren't known."

// vouchWord names what vouches for a program; adminWhere is where its
// commands are typed.
const (
	vouchWord  = "Signature"
	adminWhere = "type one of these in a command window opened as administrator (or answer ABA's first popup about it)"
)

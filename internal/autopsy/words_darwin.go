package autopsy

const pcWord = "Mac"

// limits is what the flight recorder can't see on macOS, said after "no sign".
const limits = "ABA sees a file being opened through Apple's eslogger. A program that has your browser or another app hand it the data (through a debugging port, an AppleScript, or code injected into it) shows up as that app opening the file, not as itself, and connections it had already closed aren't known."

// vouchWord names what vouches for a program; adminWhere is where its
// commands are typed.
const (
	vouchWord  = "Signature"
	adminWhere = "type one of these in Terminal, with sudo in front (or answer ABA's first popup about it)"
)

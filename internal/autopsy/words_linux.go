package autopsy

const pcWord = "computer"

// limits is what the flight recorder can't see on Linux, said after "no sign".
const limits = "ABA sees a file being opened through the kernel (fanotify). A program that reads the raw disk, reads the file through a second name it gave it in another folder before ABA looked, or has your browser hand it the data (through its debugging port, or code injected into it) doesn't show up as opening it, and connections it had already closed aren't known."

// vouchWord names what vouches for a program; adminWhere is where its
// commands are typed.
const (
	vouchWord  = "Package"
	adminWhere = "type one of these in a terminal, with sudo in front (or answer ABA's first popup about it)"
)

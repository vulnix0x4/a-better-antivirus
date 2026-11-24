package autopsy

const pcWord = "PC"

// limits is what the flight recorder can't see on Windows, said after "no sign".
const limits = "ABA sees a file being opened through Windows' own file auditing. A program that reads the disk underneath the file system, reads a shadow copy, or has your browser hand it the data (through its debugging port, or code injected into it) doesn't show up as opening the file, and connections it had already closed aren't known."

package platform

// PC is what ABA calls the computer it runs on, in the middle of a sentence:
// on Linux, often a server.
const PC = "machine"

// CleanupStep is the last thing to do after a critical detection.
const CleanupStep = "Strongly consider reinstalling the system: stealers often drop more malware. At the least, look for anything you don't recognise in your crontab (crontab -l), ~/.config/autostart and your systemd user units (systemctl --user list-unit-files)."

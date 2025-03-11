package bios9.rfid.proxmark

class Pm3CommandException(command: String, exitCode: Int, output: String) :
    RuntimeException("Command '$command' failed with exit code $exitCode:\n$output")

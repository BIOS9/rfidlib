package bios9.rfid.proxmark

class ProxmarkWslClient(
    private val wslDistro: String? = null, // WSL distribution to use, NULL to use default
    private val pm3Path: String = "~/proxmark3/client/proxmark3", // The path to the **compiled** proxmark 3 client
    private val pm3Port: String = "/dev/ttyACM0", // Proxmark serial port within WSL2
    private val debug: Boolean
) : ProxmarkClient {
    override fun runCommand(command: String): String {
        val wslCommand = mutableListOf("wsl")

        if (!wslDistro.isNullOrEmpty()) {
            wslCommand.addAll(listOf("-d", wslDistro))
        }

        if (command.contains("\"")) {
            throw IllegalArgumentException("Commands with double quotes are not supported")
        }

        wslCommand.addAll(
            listOf("--", pm3Path, "-p", pm3Port, "-f", "--incognito", "-c", "\"$command\"")
        )

        if (debug) {
            println("PM3 command:\n$wslCommand")
        }
        val process = ProcessBuilder(wslCommand).redirectErrorStream(true).start()
        process.waitFor()

        val exitCode = process.exitValue()
        val output = process.inputReader().readText();

        if (debug) {
            println("PM3 output:\n$output")
        }

        if (exitCode != 0) {
            throw Pm3CommandException(command, exitCode, output)
        }

        return output.lineSequence()
            .dropWhile { !it.startsWith("[usb|script] pm3 -->") }
            .drop(1)
            .joinToString("\n")
            .trim()
    }
}

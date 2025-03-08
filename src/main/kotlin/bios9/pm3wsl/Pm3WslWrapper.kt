package bios9.pm3wsl

class Pm3WslWrapper(
    val wslDistro: String? = null,              // WSL distribution to use, NULL to use default
    val pm3Path: String = "~/proxmark3/client/proxmark3",    // The path to the **compiled** proxmark 3 client
    val pm3Port: String = "/dev/ttyACM0"        // Proxmark serial port within WSL2
) {
    data class Hf14aTag(
        val uid:    ByteArray,
        val atqa:   ByteArray,
        val sak:    Byte,
        val ats:    ByteArray
    )

    fun runCommand(command: String): String {
        val wslCommand = mutableListOf("wsl")

        if (!wslDistro.isNullOrEmpty()) {
            wslCommand.addAll(listOf("-d", wslDistro))
        }

        if (command.contains("\"")) {
            throw IllegalArgumentException("Commands with double quotes are not supported")
        }

        wslCommand.addAll(listOf("--", pm3Path, "-p", pm3Port, "-f", "--incognito", "-c", "\"$command\""))
        val process = ProcessBuilder(wslCommand)
            .redirectErrorStream(true)
            .start()
        process.waitFor()
        return process.inputReader().readText()
    }

    fun ping() {
        runCommand("hw ping")
    }

    fun getTagDetails() : Hf14aTag {
        val strResult = runCommand("hf 14a reader")

        val uidRegex = """\[\+\]  UID:\s+([\dA-F ]+)""".toRegex()
        val atqaRegex = """\[\+\] ATQA:\s+([\dA-F ]+)""".toRegex()
        val sakRegex = """\[\+\]  SAK:\s+([\dA-F ]+)""".toRegex()
        val atsRegex = """\[\+\]  ATS:\s+([\dA-F ]+)""".toRegex()

        fun extractBytes(regex: Regex): ByteArray {
            val match = regex.find(strResult)?.groupValues?.get(1) ?: ""
            return match.split(" ").filter { it.isNotEmpty() }
                .map { it.toInt(16).toByte() }
                .toByteArray()
        }

        return Hf14aTag(
            uid = extractBytes(uidRegex),
            atqa = extractBytes(atqaRegex),
            sak = extractBytes(sakRegex)[0],
            ats = extractBytes(atsRegex)
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun tranceive(apdu: ByteArray): ByteArray? {
        val strResult = runCommand("hf 14a apdu -s -d ${apdu.toHexString()}")
        val responseRegex = """\[\+\] <<<\s+([0-9A-F]+)""".toRegex()
        val matchResult = responseRegex.find(strResult)

        return matchResult?.groupValues?.get(1)  // This will be the part of the string we need
            ?.chunked(2)                          // Split by spaces into hex values
            ?.map { it.toInt(16).toByte() }        // Convert hex to byte
            ?.toByteArray()                        // Convert list to ByteArray
    }
}
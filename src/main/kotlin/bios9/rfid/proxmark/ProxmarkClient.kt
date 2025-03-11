package bios9.rfid.proxmark

interface ProxmarkClient {
    fun runCommand(command: String): String
}
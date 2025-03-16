package bios9.rfid.proxmark;

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.classic.MifareTagSize

@OptIn(ExperimentalUnsignedTypes::class)
class ProxmarkMifareClassic(
    private val client: ProxmarkClient,
) : MifareClassic {
    private var lastKey : UByteArray? = null
    private var lastKeyType : MifareKeyType = MifareKeyType.KeyA
    private var lastAuthedSector : Int = 0

    /**
     * Attempts to authenticate to specified sector with specified key, and saves the key for future operations.
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType) {
        var command = StringBuilder("hf mf chk ")
            .append(if (keyType == MifareKeyType.KeyA) "-a " else "-b ")
            .append("-k ${key.toHexString(HexFormat.UpperCase)} ")
            .append("--no-default ")
            .append("--tblk ${MifareClassic.sectorToBlock(sector)}")
            .toString()
        val result = client.runCommand(command)

        // Regex to find valid keys in the key A or key B columns (12-character hex key)
        val keyFoundRegex = """\s*\d{3}\s*\|\s*\d{3}\s*\|\s*(:?(:?([A-F0-9]{12})\s*\|\s*1)|(:?-{12}\s*\|\s*0\s*\|\s*([A-F0-9]{12})))""".toRegex()

        // If we find a match, authentication was successful
        if (!keyFoundRegex.containsMatchIn(result)) {
            throw Exception("Authentication failed $sector, ${key.toHexString(HexFormat.UpperCase)}, $keyType")
        }

        lastAuthedSector = sector
        lastKey = key
        lastKeyType = keyType
    }

    override fun getSize(): MifareTagSize {
        TODO("Not yet implemented")
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun readBlock(block: Int): UByteArray {
        checkAuth(MifareClassic.blockToSector(block))

        var command = StringBuilder("hf mf rdbl ")
            .append("--blk $block ")
            .append(if (lastKeyType == MifareKeyType.KeyA) "-a " else "-b ")
            .append("-k ${lastKey!!.toHexString(HexFormat.UpperCase)}")
            .toString()
        val result = client.runCommand(command)

        val match = Regex("""\| ((?:[0-9A-F]{2} ){16})\|""").find(result)
        if (match != null && match.groups[1] != null) {
            return match.groups[1]!!.value
                .replace(" ", "")
                .chunked(2)
                .map {  it.toUByte(16) }
                .toUByteArray()
        }
        throw Exception("Invalid proxmark response")
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun writeBlock(block: Int, data: UByteArray) {
        checkAuth(MifareClassic.blockToSector(block))

        var command = StringBuilder("hf mf wrbl ")
            .append("--blk $block ")
            .append(if (lastKeyType == MifareKeyType.KeyA) "-a " else "-b ")
            .append("-k ${lastKey!!.toHexString(HexFormat.UpperCase)} ")
            .append("--data ${data.toHexString(HexFormat.UpperCase)} ")
            .append("--force")
            .toString()
        client.runCommand(command)
    }

    private fun checkAuth(sector: Int) {
        if (lastKey == null) throw IllegalStateException("Not authenticated")
        if (lastAuthedSector != sector) throw IllegalStateException("Not authenticated for sector $sector")
    }
}

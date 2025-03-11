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
     * Proxmark3 doesn't have a MIFARE Classic "authenticate" command like the Android API.
     * This means I just have to fake the authentication by saving the key for the next read/write.
     */
    override fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType) {
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

    override fun writeBlock(block: Int, data: UByteArray) {
        checkAuth(MifareClassic.blockToSector(block))
        TODO("Not yet implemented")
    }

    private fun checkAuth(sector: Int) {
        if (lastKey == null) throw IllegalStateException("Not authenticated")
        if (lastAuthedSector != sector) throw IllegalStateException("Not authenticated for sector $sector")
    }
}

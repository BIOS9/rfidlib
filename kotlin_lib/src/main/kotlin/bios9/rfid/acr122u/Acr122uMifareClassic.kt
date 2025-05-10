package bios9.rfid.acr122u

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.classic.MifareTagSize
import javax.smartcardio.CommandAPDU
import javax.smartcardio.TerminalFactory

@OptIn(ExperimentalUnsignedTypes::class)
class Acr122uMifareClassic : MifareClassic {
    override fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType) {
        val terminal = TerminalFactory.getDefault().terminals().list().first()
        terminal.waitForCardPresent(0)

        val card = terminal.connect("*")
        val channel = card.basicChannel

        val authData = ubyteArrayOf(
            0x01u,                // Version?
            0x00u,                // Always 0x00
            MifareClassic.sectorToBlock(sector).toUByte(), // Block #
            if (keyType == MifareKeyType.KeyA) 0x60u else 0x61u,       // Key Type: 0x60 = Key A, 0x61 = Key B
            0x00u                 // Key location in reader (0x00 = first slot)
        ) + key

        val authCmd = CommandAPDU(0xFF, 0x86, 0x00, 0x00, authData.toByteArray())
        val authResp = channel.transmit(authCmd)

        if (authResp.sw != 0x9000) {
            throw Exception("Authentication failed: SW=${Integer.toHexString(authResp.sw)}")
        }

        println("Auth success.")
    }

    override fun getSize(): MifareTagSize {
        TODO("Not yet implemented")
    }

    override fun readBlock(block: Int): UByteArray {
        TODO("Not yet implemented")
    }

    override fun writeBlock(block: Int, data: UByteArray) {
        TODO("Not yet implemented")
    }
}
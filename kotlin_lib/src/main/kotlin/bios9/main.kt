package bios9

import bios9.rfid.acr122u.Acr122uMifareClassic
import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType

@OptIn(ExperimentalUnsignedTypes::class)
fun main() {
    val mfc = Acr122uMifareClassic()
    mfc.authenticateSector(1, MifareClassic.DEFAULT_KEY, MifareKeyType.KeyA)
}
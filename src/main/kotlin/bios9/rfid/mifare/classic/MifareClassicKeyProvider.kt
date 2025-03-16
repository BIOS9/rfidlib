package bios9.rfid.mifare.classic

fun interface MifareClassicKeyProvider {
    fun authenticate(tag: MifareClassic, sector: Int)
}
package bios9.rfid.proxmark

@OptIn(ExperimentalUnsignedTypes::class)
class ProxmarkApdu(
    private val client: ProxmarkClient,
) {
  data class Hf14aTag(val uid: ByteArray, val atqa: ByteArray, val sak: Byte, val ats: ByteArray)

  fun getTagDetails(): Hf14aTag {
    val strResult = client.runCommand("hf 14a reader")

    val uidRegex = """\[\+\]  UID:\s+([\dA-F ]+)""".toRegex()
    val atqaRegex = """\[\+\] ATQA:\s+([\dA-F ]+)""".toRegex()
    val sakRegex = """\[\+\]  SAK:\s+([\dA-F ]+)""".toRegex()
    val atsRegex = """\[\+\]  ATS:\s+([\dA-F ]+)""".toRegex()

    fun extractBytes(regex: Regex): ByteArray {
      val match = regex.find(strResult)?.groupValues?.get(1) ?: ""
      return match.split(" ").filter { it.isNotEmpty() }.map { it.toInt(16).toByte() }.toByteArray()
    }

    return Hf14aTag(
        uid = extractBytes(uidRegex),
        atqa = extractBytes(atqaRegex),
        sak = extractBytes(sakRegex)[0],
        ats = extractBytes(atsRegex))
  }

  @OptIn(ExperimentalStdlibApi::class)
  fun tranceive(apdu: ByteArray): ByteArray? {
    val strResult = client.runCommand("hf 14a apdu -s -d ${apdu.toHexString()}")
    val responseRegex = """\[\+\] <<<\s+([0-9A-F]+)""".toRegex()
    val matchResult = responseRegex.find(strResult)

    return matchResult
        ?.groupValues
        ?.get(1) // This will be the part of the string we need
        ?.chunked(2) // Split by spaces into hex values
        ?.map { it.toInt(16).toByte() } // Convert hex to byte
        ?.toByteArray() // Convert list to ByteArray
  }
}

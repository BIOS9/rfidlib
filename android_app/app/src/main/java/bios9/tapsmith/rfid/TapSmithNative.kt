package bios9.tapsmith.rfid

data class GallagherCredential(
    val regionCode: Int,
    val facilityCode: Int,
    val cardNumber: Int,
    val issueLevel: Int,
) {
    val regionCodeLetter: Char = 'A' + regionCode
}

sealed interface DecodeResult {
    data class Success(val credential: GallagherCredential) : DecodeResult
    data class Error(val status: Int) : DecodeResult
    data object Unavailable : DecodeResult
}

object TapSmithNative {
    private const val STATUS_OK = 0

    val isAvailable: Boolean = runCatching {
        System.loadLibrary("tapsmith_android")
    }.isSuccess

    external fun abiVersion(): Int

    private external fun decodeGallagherCredential(data: ByteArray, outFields: IntArray): Int

    fun decodeGallagher(data: ByteArray): DecodeResult {
        if (!isAvailable) {
            return DecodeResult.Unavailable
        }

        val fields = IntArray(4)
        val status = decodeGallagherCredential(data, fields)
        if (status != STATUS_OK) {
            return DecodeResult.Error(status)
        }

        return DecodeResult.Success(
            GallagherCredential(
                regionCode = fields[0],
                facilityCode = fields[1],
                cardNumber = fields[2],
                issueLevel = fields[3],
            )
        )
    }
}

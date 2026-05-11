package bios9.tapsmith.rfid

import android.nfc.tech.IsoDep

data class GallagherCredential(
    val regionCode: Int,
    val facilityCode: Int,
    val cardNumber: Int,
    val issueLevel: Int,
    val applicationId: Int,
) {
    val regionCodeLetter: Char = 'A' + regionCode
    val applicationIdHex: String = "%06X".format(applicationId)
}

sealed interface DecodeResult {
    data class Success(val credentials: List<GallagherCredential>) : DecodeResult
    data class Error(val status: Int? = null, val message: String? = null) : DecodeResult
    data object Unavailable : DecodeResult
}

object TapSmithNative {
    private const val MAX_GALLAGHER_CREDENTIALS = 12
    private const val FIELDS_PER_CREDENTIAL = 5

    val isAvailable: Boolean = runCatching {
        System.loadLibrary("tapsmith_android")
    }.isSuccess

    external fun abiVersion(): Int

    private external fun readGallagherDesfire(transceiver: IsoDepTransceiver, outFields: IntArray): Int

    fun readGallagherDesfire(isoDep: IsoDep): DecodeResult {
        if (!isAvailable) {
            return DecodeResult.Unavailable
        }

        val fields = IntArray(MAX_GALLAGHER_CREDENTIALS * FIELDS_PER_CREDENTIAL)
        val count = readGallagherDesfire(IsoDepTransceiver(isoDep), fields)
        if (count <= 0) {
            return DecodeResult.Error(status = count)
        }

        return DecodeResult.Success(
            credentials = (0 until count).map { index ->
                fields.toCredential(index * FIELDS_PER_CREDENTIAL)
            },
        )
    }

    private fun IntArray.toCredential(offset: Int): GallagherCredential =
        GallagherCredential(
            regionCode = this[offset],
            facilityCode = this[offset + 1],
            cardNumber = this[offset + 2],
            issueLevel = this[offset + 3],
            applicationId = this[offset + 4],
        )
}

class IsoDepTransceiver(private val isoDep: IsoDep) {
    fun transceive(request: ByteArray): ByteArray =
        runCatching {
            isoDep.transceive(request)
        }.getOrDefault(ByteArray(0))
}

package bios9.rfid.mifare.mad

/**
 * An Application ID (AID) in the Mifare Application Directory (MAD).
 *
 * Registered function cluster codes can be found in https://www.nxp.com/docs/en/application-note/AN10787.pdf
 */
class MadAid private constructor(
    val rawValue: UShort
) {
    companion object {
        fun fromRaw(rawValue: UShort): MadAid {
            return MadAid(rawValue)
        }

        fun fromRaw(functionClusterCode: UByte, applicationCode: UByte): MadAid {
            return fromRaw(
                ((functionClusterCode.toUInt() shl 8) or applicationCode.toUInt()).toUShort()
            )
        }

        fun fromAdministrationCode(administrationCode: MadAdministrationCode): MadAid {
            return fromRaw(
                administrationCode.applicationCode!!.toUShort()
            )
        }

        fun fromFunction(functionCluster: MadFunctionCluster, applicationCode: UByte): MadAid {
            return MadAid(
                ((functionCluster.functionClusterCode!!.toUInt() shl 8) or applicationCode.toUInt()).toUShort(),
            )
        }
    }

    val functionClusterCode = (rawValue.toUInt() shr 8).toUByte()
    val functionCluster = MadFunctionCluster.fromFunctionClusterCode(functionClusterCode)
    val applicationCode = (rawValue.toUInt() and 0xFFu).toUByte()

    // If the function cluster is zero, the application code is treated as an administration code according to the spec.
    val administrationCode: MadAdministrationCode? =
        if (functionClusterCode == 0u.toUByte()) MadAdministrationCode.fromApplicationCode(applicationCode) else null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MadAid

        return rawValue == other.rawValue
    }

    override fun hashCode(): Int {
        return rawValue.hashCode()
    }
}
package bios9.rfid.mifare

/**
 * An Application ID (AID) in the Mifare Application Directory (MAD).
 *
 * Registered function cluster codes can be found in https://www.nxp.com/docs/en/application-note/AN10787.pdf
 */
class MadAid private constructor(
    val rawValue: UShort,
    val functionClusterCode: UByte,
    val applicationCode: UByte
) {
    companion object {
        fun fromFunction(functionClusterCode: UByte, applicationCode: UByte): MadAid {
            return MadAid(
                (applicationCode.toUInt() or (functionClusterCode.toUInt() shl 8)).toUShort(),
                functionClusterCode,
                applicationCode
            )
        }

        fun fromRaw(rawValue: UShort): MadAid {
            return MadAid(
                rawValue,
                (rawValue.toUInt() shr 8).toUByte(),
                (rawValue.toUInt() and 0xFFu).toUByte()
            )
        }
    }

    private val functionCodeMap: Map<UInt, String> = mapOf(
        0x00u to "Card Administration",
        0x01u to "Miscellaneous Applications",
        0x02u to "Miscellaneous Applications",
        0x03u to "Miscellaneous Applications",
        0x04u to "Miscellaneous Applications",
        0x05u to "Miscellaneous Applications",
        0x06u to "Miscellaneous Applications",
        0x07u to "Miscellaneous Applications",
        0x08u to "Airlines",
        0x09u to "Ferry Traffic",
        0x10u to "Railway Services",
        0x11u to "Miscellaneous Applications",
        0x12u to "Transport",
        0x14u to "Security Solutions",
        0x18u to "City Traffic",
        0x19u to "Czech Railways",
        0x20u to "Bus Services",
        0x21u to "Multi-Modal Transit",
        0x28u to "Taxi",
        0x30u to "Road Toll",
        0x31u to "Generic Transport",
        0x38u to "Company Services",
        0x40u to "City Card Services",
        0x47u to "Access Control & Security",
        0x48u to "Access Control & Security",
        0x49u to "VIGIK",
        0x4Au to "Ministry of Defence, Netherlands",
        0x4Bu to "Bosch Telecom, Germany",
        0x4Cu to "European Union Institutions",
        0x50u to "Ski Ticketing",
        0x51u to "Access Control & Security",
        0x52u to "Access Control & Security",
        0x53u to "Access Control & Security",
        0x54u to "Access Control & Security",
        0x55u to "SOAA Standard for Offline Access",
        0x58u to "Academic Services",
        0x60u to "Food",
        0x68u to "Non-Food Trade",
        0x70u to "Hotel",
        0x71u to "Loyalty",
        0x75u to "Airport Services",
        0x78u to "Car Rental",
        0x79u to "Dutch Government",
        0x80u to "Administration Services",
        0x88u to "Electronic Purse",
        0x90u to "Television",
        0x91u to "Cruise Ship",
        0x95u to "IOPTA",
        0x97u to "Metering",
        0x98u to "Telephone",
        0xA0u to "Health Services",
        0xA8u to "Warehouse",
        0xB0u to "Electronic Trade",
        0xB8u to "Banking",
        0xC0u to "Entertainment & Sports",
        0xC8u to "Car Parking",
        0xC9u to "Fleet Management",
        0xD0u to "Fuel, Gasoline",
        0xD8u to "Info Services",
        0xE0u to "Press",
        0xE1u to "NFC Forum",
        0xE8u to "Computer",
        0xF0u to "Mail",
        0xF8u to "Miscellaneous Applications",
        0xF9u to "Miscellaneous Applications",
        0xFAu to "Miscellaneous Applications",
        0xFBu to "Miscellaneous Applications",
        0xFCu to "Miscellaneous Applications",
        0xFDu to "Miscellaneous Applications",
        0xFEu to "Miscellaneous Applications",
        0xFFu to "Miscellaneous Applications"
    )

    val functionCluster = functionCodeMap[functionClusterCode.toUInt()] ?: "Unknown/Reserved Function Code"

    enum class AdministrationCode(val applicationCode: UByte) {
        FREE(0x00u),
        DEFECT(0x01u),
        RESERVED(0x02u),
        ADDITIONAL_DIRECTORY_INFO(0x03u),
        CARDHOLDER_INFO(0x04u),
        NOT_APPLICABLE(0x05u),
        UNKNOWN(0xFFu);

        companion object {
            fun fromApplicationCode(code: UByte): AdministrationCode {
                return entries.find { it.applicationCode == code } ?: UNKNOWN
            }
        }
    }

    // If the function cluster is zero, the application code is treated as an administration code according to the spec.
    val administrationCode: AdministrationCode? =
        if (functionClusterCode == 0u.toUByte()) AdministrationCode.fromApplicationCode(applicationCode) else null
}
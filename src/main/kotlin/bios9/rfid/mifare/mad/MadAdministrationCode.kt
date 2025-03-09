package bios9.rfid.mifare.mad

enum class MadAdministrationCode(val applicationCode: UByte?, val description: String) {
    FREE(0x00u, "Sector is free"),
    DEFECT(0x01u, "Sector is defective, e.g. access keys are destroyed or unknown"),
    RESERVED(0x02u, "Sector is reserved"),
    ADDITIONAL_DIRECTORY_INFO(0x03u, "Sector contains additional directory info (useful only for future cards)"),
    CARDHOLDER_INFO(0x04u, "Sector contains card holder information in ASCII format"),
    NOT_APPLICABLE(0x05u, "Sector not applicable (above memory size)"),
    UNKNOWN(null, "Unknown administration code");

    companion object {
        private val map = MadAdministrationCode.entries.associateBy(MadAdministrationCode::applicationCode)

        fun fromApplicationCode(code: UByte): MadAdministrationCode = map[code] ?: UNKNOWN
    }
}
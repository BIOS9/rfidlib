package bios9.rfid.gallagher.exceptions

class InvalidGallagherCredential(
    sector: Int
) : RuntimeException("Sector $sector doesn't contain a Gallagher credential or the credential is invalid")
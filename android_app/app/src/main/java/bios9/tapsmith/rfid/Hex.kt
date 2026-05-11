package bios9.tapsmith.rfid

fun ByteArray.toHexString(separator: String = ""): String =
    joinToString(separator) { byte -> "%02X".format(byte.toInt() and 0xFF) }

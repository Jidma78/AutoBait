def decode_tcp_flag(tcp_flag):
    """
    Decode a TCP flag integer into a human-readable string.
    """
    flag_map = {
        0x02: "[SYN]",
        0x10: "[ACK]",
        0x12: "[SYN-ACK]",
        0x08: "[PUSH]",
        0x18: "[PUSH-ACK]",
        0x11: "[FIN-ACK]",
        0x04: "[RST]",
        0x14: "[RST-ACK]",
        0x20: "[URG]",
    }
    return flag_map.get(int(tcp_flag), f"[UNKNOWN FLAG: {tcp_flag}]")

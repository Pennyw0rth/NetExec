# Original from here: https://github.com/nopfor/ntlm_challenger

import datetime

from impacket.smb3 import WIN_VERSIONS


def decoder(byte_string, decode_type):
    if decode_type == "byte":
        return byte_string.decode("UTF-8").replace("\x00", "")
    else:
        return int.from_bytes(byte_string, "little")


def parse_version(version_bytes):
    product_build = decoder(version_bytes[2:4], "int")
    return f"{WIN_VERSIONS[product_build]} Build {product_build}"


def parse_target_info(target_info_bytes):
    MsvAvEOL = 0x0000
    MsvAvNbComputerName = 0x0001
    MsvAvNbDomainName = 0x0002
    MsvAvDnsComputerName = 0x0003
    MsvAvDnsDomainName = 0x0004
    MsvAvDnsTreeName = 0x0005
    MsvAvFlags = 0x0006
    MsvAvTimestamp = 0x0007
    MsvAvSingleHost = 0x0008
    MsvAvTargetName = 0x0009
    MsvAvChannelBindings = 0x000A

    target_info = {
        "MsvAvNbComputerName": None,
        "MsvAvDnsDomainName": None,
    }
    info_offset = 0

    while info_offset < len(target_info_bytes):
        av_id = decoder(target_info_bytes[info_offset:info_offset + 2], "int")
        av_len = decoder(target_info_bytes[info_offset + 2:info_offset + 4], "int")
        av_value = target_info_bytes[info_offset + 4:info_offset + 4 + av_len]

        info_offset = info_offset + 4 + av_len

        if av_id == MsvAvEOL:
            pass
        elif av_id == MsvAvNbComputerName:
            target_info["MsvAvNbComputerName"] = decoder(av_value, "byte")
        elif av_id == MsvAvNbDomainName:
            target_info["MsvAvNbDomainName"] = decoder(av_value, "byte")
        elif av_id == MsvAvDnsComputerName:
            target_info["MsvAvDnsComputerName"] = decoder(av_value, "byte")
        elif av_id == MsvAvDnsDomainName:
            target_info["MsvAvDnsDomainName"] = decoder(av_value, "byte")
        elif av_id == MsvAvDnsTreeName:
            target_info["MsvAvDnsTreeName"] = decoder(av_value, "byte")
        elif av_id == MsvAvFlags:
            pass
        elif av_id == MsvAvTimestamp:
            filetime = decoder(av_value, "int")
            microseconds = (filetime - 116444736000000000) / 10
            time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=microseconds)
            target_info["MsvAvTimestamp"] = time.strftime("%b %d, %Y %H:%M:%S.%f")
        elif av_id == MsvAvSingleHost:
            target_info["MsvAvSingleHost"] = decoder(av_value, "byte")
        elif av_id == MsvAvTargetName:
            target_info["MsvAvTargetName"] = decoder(av_value, "byte")
        elif av_id == MsvAvChannelBindings:
            target_info["MsvAvChannelBindings"] = av_value
    return target_info


def parse_challenge(challenge_message):
    # TargetNameFields
    target_name_fields = challenge_message[12:20]
    target_name_len = decoder(target_name_fields[0:2], "int")
    target_name_offset = decoder(target_name_fields[4:8], "int")

    # TargetInfoFields
    target_info_fields = challenge_message[40:48]
    target_info_len = decoder(target_info_fields[0:2], "int")
    target_info_offset = decoder(target_info_fields[4:8], "int")

    # Version
    version = None
    version_bytes = challenge_message[48:56]
    version = parse_version(version_bytes)

    # TargetName
    target_name = challenge_message[target_name_offset:target_name_offset + target_name_len]
    target_name = decoder(target_name, "byte")

    # TargetInfo
    target_info_bytes = challenge_message[target_info_offset:target_info_offset + target_info_len]

    target_info = parse_target_info(target_info_bytes)

    return {
        "target_name": target_name,
        "version": version,
        "target_info": target_info
    }

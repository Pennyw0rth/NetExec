#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DCERPCSessionError.py
# Author             : Podalirius (@podalirius_)
# Date created       : 15 Sep 2022

from impacket import system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code
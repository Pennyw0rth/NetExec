from argparse import ArgumentDefaultsHelpFormatter, SUPPRESS, OPTIONAL, ZERO_OR_MORE

class DisplayDefaultsNotNone(ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action):
        help_string = action.help
        if "%(default)" not in action.help and action.default is not SUPPRESS:
            defaulting_nargs = [OPTIONAL, ZERO_OR_MORE]
            if (action.option_strings or action.nargs in defaulting_nargs) and action.default:  # Only add default info if it's not None
                help_string += " (default: %(default)s)"  # NORUFF
        return help_string
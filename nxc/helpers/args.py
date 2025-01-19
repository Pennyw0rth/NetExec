from argparse import ArgumentDefaultsHelpFormatter, SUPPRESS, OPTIONAL, ZERO_OR_MORE
from argparse import Action

class DisplayDefaultsNotNone(ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action):
        help_string = action.help
        if "%(default)" not in action.help and action.default is not SUPPRESS:
            defaulting_nargs = [OPTIONAL, ZERO_OR_MORE]
            if (action.option_strings or action.nargs in defaulting_nargs) and action.default:  # Only add default info if it's not None
                help_string += " (default: %(default)s)"  # NORUFF
        return help_string


class DefaultTrackingAction(Action):
    def __init__(self, option_strings, dest, default=None, required=False, **kwargs):
        # Store the default value to check later
        self.default_value = default
        super().__init__(
            option_strings, dest, default=default, required=required, **kwargs
        )

    def __call__(self, parser, namespace, values, option_string=None):
        # Set an attribute to track whether the value was explicitly set
        setattr(namespace, self.dest, values)
        setattr(namespace, f"{self.dest}_explicitly_set", True)

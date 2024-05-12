# List of imports to look out for that can enable backdoors in your code.
import_list = [
    "httplib",
    "urllib",
    "urllib2",
    "socket",
    "urllib3",
    "http.client",
    "requests",
    "aiohttp",
    "selenium",
    "grpcio",
]

# List of external command executions that can be malicious
command_list = [
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_call",
    "pexpect",
]


def scan_imports(lines_by_file):
    """
    Scans the lines that were provided from each file to look for potentially harmful imports
    that are being used.

    Args:
    lines_by_file (dict): Dictionary object that contains the lines in each file provided.

    Returns:
    dictionary object with the lines that were flagged by this scan
    """
    suspicious_lines = {}
    for file in lines_by_file:
        suspicious_lines[file] = []
        print(f"Scanning file {file} for potentially malicious imports")
        for line in lines_by_file[file]:
            if "import" in line[1]:
                for import_name in import_list:
                    if import_name in line[1]:
                        suspicious_lines[file].append(line)

    return suspicious_lines


def scan_commands(lines_by_file):
    """
    Scans the lines that were provided from each file to look for potentially harmful commands
    that are being used.

    Args:
    lines_by_file (dict): Dictionary object that contains the lines in each file provided.

    Returns:
    dictionary object with the lines that were flagged by this scan
    """
    suspicious_lines = {}
    for file in lines_by_file:
        suspicious_lines[file] = []
        print(f"Scanning file {file} for potentially malicious commands")
        for line in lines_by_file[file]:
            for command in command_list:
                if command in line[1]:
                    suspicious_lines[file].append(line)

    return suspicious_lines

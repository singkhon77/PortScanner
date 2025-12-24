# - intereac
# - validate output/
# -- ip or hostname/
# -- port range 0-65535
# -- Error handleing
# - scanner funtion
# - socket creation
# - connection attempt -> close sockets
# - output
# - reporting format
# - custom list of port
# - scan mode (quick scan, Thorough scan- all 0-65535)

import socket
import argparse
import re
import pathlib

parser = argparse.ArgumentParser(description='Description of the program: This program is used to scan port')

parser.add_argument('--mode', type=str, required=False, help='choose mode quick scan(q) scan common ports, Thorough scan(t) scan all 0-65535 ports or Custom scan(c) input list ex.21,22,80')
parser.add_argument('--output', type=str, required=False, help='chose to display only open ports(o), close ports(c)')
parser.add_argument('--mTarget', type=pathlib.Path, required=False, help='list text file of target IPs')
parser.add_argument('--log', type=str, required=False, help='log output into text file by input text file name')
parser.add_argument('--service', choices=['t', 'f'], default='f', required=False ,help='enable service detection: t = enable, f = disable (default f)')


args = parser.parse_args()

log_file = None

def log_print(message):
    print(message)
    if log_file:
        try:
            log_file.write(message + "\n")
        except Exception as e:
            print(f"[ X ] Logging error: {e}")



def scan_port(target, port, show_service=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        service = ""
        if show_service and result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

        if args.output == "o":
            if result == 0:
                if show_service:
                    log_print(f"{port}     open     service: {service}")
                else:
                    log_print(f"{port}     open")
        elif args.output == "c":
            if result != 0:
                log_print(f"{port}     closed")
        else:
            if result == 0:
                if show_service:
                    log_print(f"{port}     open     service: {service}")
                else:
                    log_print(f"{port}     open")
            else:
                log_print(f"{port}     closed")

    except socket.timeout:
        log_print(f"{port}     timed out")

    except Exception as e:
        log_print(f"An error occurred while scanning port {port}: {e}")

    finally:
        sock.close()



def parse_custom_ports(port_input):
    ports = set()
    parts = port_input.split(",")

    for p in parts:
        if "-" in p:
            start, end = p.split("-")
            if start.isdigit() and end.isdigit():
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
                else:
                    raise ValueError("Invalid range in custom ports")
            else:
                raise ValueError("Port range must be digits")
        else:
            if p.isdigit():
                num = int(p)
                if 1 <= num <= 65535:
                    ports.add(num)
                else:
                    raise ValueError("Port value out of range")
            else:
                raise ValueError("Invalid port value in custom list")

    return sorted(ports)


def load_targets_from_file(file_path):
    ip_regex = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')
    targets = []

    try:
        with open(file_path, "r") as f:
            for line in f:
                target = line.strip()
                if not target:
                    continue
                if ip_regex.match(target) or "." in target:
                    targets.append(target)
                else:
                    print(f"Skipped invalid target: {target}")
    except FileNotFoundError:
        print(f"[ X ] File not found: {file_path}")
        exit(1)

    if not targets:
        print("[ X ] No valid targets found in the file")
        exit(1)

    return targets



def userInput():
    import re

    ip_regex = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')

    # check ip input
    while True:
        target = input("Enter target IP address: ")
        if ip_regex.match(target) or (not target.isdigit() and "." in target):
            break
        else:
            print("[ X ] Invalid IP. Try again!")


    # check ports input
    while True:
        start_port = input("Enter the starting port: ")
        end_port = input("Enter the ending port: ")

        if (
            start_port.isdigit() and
            end_port.isdigit() and
            1 <= int(start_port) <= 65535 and
            1 <= int(end_port) <= 65535 and
            int(start_port) <= int(end_port)
        ):
            start_port = int(start_port)
            end_port = int(end_port)
            break
        else:
            print("[ X ] Invalid port range. Ports must be 1-65535 and start ≤ end. Try again!")
    print(f"Scanning {target} ports {start_port}-{end_port}...")
    return target, start_port, end_port

def userInputQuick():
    import re

    ip_regex = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')

    # check ip input
    while True:
        target = input("Enter target IP address: ")
        if ip_regex.match(target) or (not target.isdigit() and "." in target):
            break
        else:
            print("[ X ] Invalid IP. Try again!")


    print(f"Scanning common ports in {target}...")
    return target

def userInput_custom():
    ip_regex = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')

    while True:
        target = input("Enter target IP address: ")
        if ip_regex.match(target) or (not target.isdigit() and "." in target):
            break
        else:
            print("[ X ] Invalid IP. Try again!")

    while True:
        ports_str = input("Enter custom port list (ex: 20-25,80,443): ")
        try:
            port_list = parse_custom_ports(ports_str)
            break
        except ValueError as e:
            print(f"[ X ] {e}. Try again!")

    print(f"Custom scanning ports on {target}...")
    return target, port_list


def main():

    # check multi taget file
    if args.mTarget:
        targets = load_targets_from_file(args.mTarget)
    else:
        targets = None

    # check service scan
    show_service = True if args.service == 't' else False


    # check log file
    global log_file
    if args.log:
        try:
            log_file = open(args.log, "w")
            log_print(f"Logg to file {args.log}")
        except Exception as e:
            print(f"[ X ] Cannot open log file: {e}")
            log_file = None


    # Thorough scan
    if args.mode == "t":
        if targets:
            start_port = 0
            end_port = 65535
            for target in targets:
                print(f"\n>>> Scanning {target} ports {start_port}-{end_port}")
                print("Port     Status")
                print("----     ------")
                for port in range(start_port, end_port + 1):
                    scan_port(target, port, show_service)
        else:
            target, start_port, end_port = userInput()
            print("Port     Status")
            print("----     ------")
            for port in range(start_port, end_port + 1):
                scan_port(target, port, show_service)

    # Quick scan
    elif args.mode == "q":
        common_ports = [21, 22, 80, 88, 53, 135, 139, 389, 445, 464]
        if targets:
            for target in targets:
                print(f"\n>>> Quick scanning {target}")
                print("Port     Status")
                print("----     ------")
                for port in common_ports:
                    scan_port(target, port, show_service)
        else:
            target = userInputQuick()
            print("Port     Status")
            print("----     ------")
            for port in common_ports:
                scan_port(target, port, show_service)

    # Custom list
    elif args.mode == "c":
        if targets:
            ports_str = input("Enter custom port list: ")
            port_list = parse_custom_ports(ports_str)
            for target in targets:
                print(f"\n>>> Custom scan {target}")
                print("Port     Status")
                print("----     ------")
                for port in port_list:
                    scan_port(target, port, show_service)
        else:
            target, port_list = userInput_custom()
            print("Port     Status")
            print("----     ------")
            for port in port_list:
                scan_port(target, port, show_service)
    # Default
    else:
        if targets:
            start_port = 1
            end_port = 1024
            for target in targets:
                print(f"\n>>> Scanning {target}")
                print("Port     Status")
                print("----     ------")
                for port in range(start_port, end_port + 1):
                    scan_port(target, port, show_service)
        else:
            target, start_port, end_port = userInput()
            print("Port     Status")
            print("----     ------")
            for port in range(start_port, end_port + 1):
                scan_port(target, port, show_service)

    if log_file:
        log_file.close()
        print(f"Log saved to {args.log}")





if __name__ == "__main__":
    main()

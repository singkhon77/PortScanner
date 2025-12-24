
# Port Scanner – ReadMe

## Description

This program is a Python-based TCP port scanner.
It allows users to scan a target host or multiple hosts to determine which ports are open or closed.
It supports quick scan, full scan, and custom port scan modes, with optional service detection and logging.

---

## Features

* Scan a single target or multiple targets from a file
* Three scan modes: Quick, Thorough, and Custom
* Validate IP addresses and port ranges
* Optional service name detection
* Filter output (show only open or closed ports)
* Save results to a log file

---

## Requirements

* Python 3
* Standard libraries only (socket, argparse, pathlib, re)

---

## Usage

Basic format:

```
python scanner.py --mode <q|t|c>
```

Example:

```
python scanner.py --mode q
```

With target list:

```
python scanner.py --mode t --mTarget targets.txt
```

With logging:

```
python scanner.py --mode q --log result.txt
```

With service detection:

```
python scanner.py --mode q --service t
```

---

## Command Line Arguments

| Argument  | Description                                             |
| --------- | ------------------------------------------------------- |
| --mode    | Scan mode: q = quick, t = thorough, c = custom          |
| --output  | Output filter: o = show open only, c = show closed only |
| --mTarget | Text file containing list of target IPs or hostnames    |
| --log     | Save scan results to a log file                         |
| --service | Enable service detection (t = true, f = false)          |

---

## Scan Modes

Quick Scan (q)
Scans common ports:
21, 22, 80, 88, 53, 135, 139, 389, 445, 464

Thorough Scan (t)
Scans all ports from 0 to 65535

Custom Scan (c)
Scans user-defined ports such as:

```
20-25,80,443
```

---

## Input Validation

* IP addresses are checked using a regular expression
* Port numbers must be between 1 and 65535
* Custom port ranges must be valid

---

## Output Format

Each scan result is printed in the following format:

```
Port     Status
----     ------
80       open
443      closed
```

When service detection is enabled:

```
80       open     service: http
```

---

## Log File

If --log is specified, all scan output is saved to the given file.

Example:

```
--log scan_results.txt
```

---

## Legal Notice

This tool is intended for educational use and authorized security testing only.
Do not scan systems you do not own or have permission to test.

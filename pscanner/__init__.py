# -*- coding: utf-8 -*-

"""
The MIT License (MIT)

Copyright (c) 2022 Lee-matod

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


from __future__ import annotations

import click
import socket
import sys
import traceback
from colorama import Fore, init
from threading import Lock, Thread
from typing import TYPE_CHECKING, List, Optional, Set, Type


if TYPE_CHECKING:
    from types import TracebackType


init()

DEFAULT_PORTS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1434,
    1723,
    3306,
    3389,
    5900,
    8080,
    8443
)


class SocketHandler:
    def __init__(self, lock: Lock):
        self._lock: Lock = lock

    def __enter__(self):
        return

    def __exit__(self, exc_type: Type[Exception], exc_val: Exception, exc_tb: TracebackType):
        if exc_val is None:
            return False
        elif isinstance(exc_val, (KeyboardInterrupt, SystemExit)):
            self._locked_print(f"{Fore.RED}Exiting program.{Fore.RESET}")
        elif isinstance(exc_val, socket.gaierror):
            self._locked_print(f"{Fore.RED}[!] Hostname could not be resolved.{Fore.RESET}")
        elif isinstance(exc_val, socket.error):
            self._locked_print(f"{Fore.RED}[!] Could not connect to server.{Fore.RESET}")
        else:
            self._locked_print(
                f"{Fore.RED}[!] Unknown error:\n"
                f"{''.join(traceback.format_exception(exc_type, exc_val, exc_tb))}{Fore.RESET}"
            )
        return True

    def _locked_print(self, *args, **kwargs):
        with self._lock:
            click.echo(*args, **kwargs)
        sys.exit()


@click.command(name="pscanner")
@click.argument("target")
@click.option("--default", type=bool, help="Whether to use the preset list of ports.", required=False, default=True)
@click.option(
    "--max-threads",
    type=int,
    help="Maximum amount of threads allowed. If set to 0, as many threads will be used as possible",
    required=False,
    default=10
)
@click.option("--include", help="Additional list of ports.", required=False)
@click.option("--exclude", help="Ports that will be skipped when scanning.", required=False)
@click.option(
    "--timeout",
    help="Amount of seconds before a connection is considered timed out.",
    type=int,
    required=False,
    default=1
)
def port_scanner(
        target: str,
        default: bool = True,
        max_threads: int = 10,
        include: Optional[str] = None,
        exclude: Optional[str] = None,
        timeout: int = 1
):
    """CLI port scanner built in Python using the click module.

    This is an ethical tool made with the sole purpose to educate about cyber-security and penetration testing.
    You should not use this tool to cause any malicious or harmful things. Nevertheless, use this at your own risk.

    Additional ports can be specified in a range, or as unique ports. Ranges should be specified with a dash where the
    left number is the starting port and right is the ending port ('10-15' would evaluate to ports 10, 11, 12, 13, 14,
    and 15). Unique ports should be separated by a comma (,).

    Default list of ports are the 23 most common searched ports. This list can be disabled by setting the '--default'
    option to 'False'.
    """
    if max_threads < 0:
        click.echo(f"{Fore.RED}Maximum thread number should be a positive integer or 0{Fore.RESET}")
        sys.exit()
    target = socket.gethostbyname(target)
    click.echo("-" * 50)
    click.echo(f"{Fore.YELLOW}Scanning target:{Fore.RESET} {target}")
    if default:
        click.echo(f"{Fore.YELLOW}Default ports:{Fore.RESET} {', '.join(map(str, DEFAULT_PORTS))}")
    included_ports = parse_ports(include or "")
    excluded_ports = parse_ports(exclude or "")
    sorted_included = sorted(included_ports)
    sorted_excluded = sorted(excluded_ports)
    if sorted_included[0] <= 0 or 65535 < sorted_included[-1] or sorted_excluded[0] <= 0 or 65535 < sorted_excluded[-1]:
        click.echo("-" * 50)
        click.echo(f"{Fore.RED}Specified ports should be between 0 and 65536.{Fore.RESET}")
        sys.exit()
    if include:
        click.echo(f"{Fore.YELLOW}Additional ports:{Fore.RESET} {include}")
    if exclude:
        click.echo(f"{Fore.YELLOW}Skipping ports:{Fore.RESET} {exclude}")
    click.echo("-" * 50)

    total_ports = sorted(list(set(DEFAULT_PORTS).union(included_ports)) if default else list(included_ports))
    used_ports = [p for p in total_ports if p not in excluded_ports]
    threads = []
    with SocketHandler(Lock()):
        for p in used_ports:
            t = Thread(target=check_port, args=(target, p, timeout))
            if max_threads != 0 and len(total_ports) > max_threads:
                if len(threads) == max_threads:
                    start_threads(threads.copy())
                    threads.clear()
            threads.append(t)
        start_threads(threads)
        click.echo(f"{Fore.BLUE}Finished checking {len(total_ports)} port(s).{Fore.RESET}")
        sys.exit()


def start_threads(threads: List[Thread]):
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def check_port(target: str, port: int, timeout: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    if result == 0:
        click.echo(f"{Fore.GREEN}[@] Port {port} is open.{Fore.RESET}")
    elif result == 11:
        click.echo(f"{Fore.WHITE}[#] Port {port} timed out.{Fore.RESET}")
    s.close()


def parse_ports(ports: str) -> Set[int]:
    port_list: Set[int] = set()
    port = ""
    next_ranged: bool = False
    for char in ports:
        if char.isnumeric():
            port += char
        elif char == ",":
            assert port.isnumeric()
            if next_ranged:
                for num in range(list(port_list)[-1] + 1, int(port) + 1):
                    port_list.add(num)
                next_ranged = False
                port = ""
                continue
            port_list.add(int(port))
            port = ""
        elif char == "-":
            next_ranged = True
            assert port.isnumeric()
            port_list.add(int(port))
            port = ""
    if port:
        assert port.isnumeric()
        if next_ranged:
            for num in range(list(port_list)[-1] + 1, int(port) + 1):
                port_list.add(num)
        else:
            port_list.add(int(port))
    return port_list


if __name__ == '__init__':
    port_scanner()
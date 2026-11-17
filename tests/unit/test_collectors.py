"""Collector parsing tests using fixed system fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from ubuntuguard.collectors.accounts import collect_users, parse_group, parse_passwd
from ubuntuguard.collectors.network import (
    parse_default_gateways,
    parse_interfaces,
)
from ubuntuguard.collectors.packages import parse_upgradable
from ubuntuguard.collectors.ports import parse_ss
from ubuntuguard.collectors.processes import parse_ps
from ubuntuguard.collectors.services import parse_services
from ubuntuguard.collectors.storage import parse_mounts
from ubuntuguard.collectors.system import (
    parse_loadavg,
    parse_meminfo,
    read_cpu_model,
    read_uptime,
)

MEMINFO = """\
MemTotal:        8000000 kB
MemFree:          500000 kB
MemAvailable:    2000000 kB
Buffers:          100000 kB
Cached:          1500000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
"""

MOUNTS = """\
/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda2 /home ext4 rw 0 0
/dev/sdb1 /mnt/my\\040data xfs rw 0 0
/dev/sdc1 /media/usb vfat rw 0 0
"""

IP_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\\       valid_lft 86300sec
2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever
"""

IP_LINK = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT gr\
oup default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode\
 DEFAULT group default qlen 1000\\    link/ether 02:42:0a:00:00:05 brd ff:ff:ff:ff:ff:ff
"""

SS_OUTPUT = """\
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=700,fd=13))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))
tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))
"""

PS_OUTPUT = """\
 1234     1 root       0.5  1.2 /usr/sbin/sshd -D
  999     1 www-data   2.5  0.8 nginx: worker process
  100     2 app       10.0  5.0 python worker.py
"""

SERVICES_OUTPUT = """\
\u25cf ssh.service loaded active running OpenBSD Secure Shell server
  nginx.service loaded active running A high performance web server
"""

PASSWD = """\
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
broken:x:notint:0::/:/bin/sh
"""

GROUP = """\
root:x:0:
ubuntu:x:1000:
sudo:x:27:ubuntu
adm:x:4:ubuntu,alice
"""


def test_parse_loadavg() -> None:
    assert parse_loadavg("0.52 0.31 0.18 1/234 5678") == (0.52, 0.31, 0.18)
    assert parse_loadavg("garbage") == ()


def test_parse_meminfo() -> None:
    memory = parse_meminfo(MEMINFO)
    assert memory.total_bytes == 8000000 * 1024
    assert memory.available_bytes == 2000000 * 1024
    assert memory.used_bytes == 6000000 * 1024
    assert memory.used_percent == 75.0
    assert memory.swap_used_bytes == 500000 * 1024


def test_parse_meminfo_without_memavailable() -> None:
    text = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 150 kB\n"
    memory = parse_meminfo(text)
    assert memory.available_bytes == 300 * 1024
    assert memory.used_bytes == 700 * 1024


def test_parse_meminfo_requires_total() -> None:
    with pytest.raises(ValueError):
        parse_meminfo("MemFree: 100 kB\n")


def test_read_uptime_and_cpu_model(tmp_path: Path) -> None:
    uptime = tmp_path / "uptime"
    uptime.write_text("12345.67 999.00\n", encoding="utf-8")
    assert read_uptime(uptime) == pytest.approx(12345.67)

    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text(
        "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i5\n", encoding="utf-8"
    )
    assert read_cpu_model(cpuinfo) == "Intel(R) Core(TM) i5"

    assert read_uptime(tmp_path / "absent") is None
    assert read_cpu_model(tmp_path / "absent") == ""


def test_parse_mounts_filters_pseudo_filesystems() -> None:
    entries = parse_mounts(MOUNTS)
    filesystems = [entry[2] for entry in entries]
    assert "proc" not in filesystems
    assert "tmpfs" not in filesystems
    assert ("/dev/sdb1", "/mnt/my data", "xfs") in entries
    assert len(entries) == 4


def test_parse_interfaces_and_gateway() -> None:
    interfaces = parse_interfaces(IP_ADDR, IP_LINK)
    by_name = {interface.name: interface for interface in interfaces}
    assert set(by_name) == {"lo", "eth0"}
    assert by_name["lo"].state == "UNKNOWN"
    assert by_name["eth0"].state == "UP"
    assert by_name["eth0"].mac == "02:42:0a:00:00:05"
    assert by_name["eth0"].addresses == ("10.0.0.5/24", "fe80::1/64")

    routes = (
        "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n"
        "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n"
    )
    assert parse_default_gateways(routes) == ("10.0.0.1",)


def test_parse_ss() -> None:
    ports = parse_ss(SS_OUTPUT)
    assert len(ports) == 3
    assert ports[0].protocol == "udp"
    assert ports[0].local_address == "127.0.0.53"
    assert ports[0].port == 53
    assert ports[0].process == "systemd-resolve(700)"
    assert ports[1].port == 22
    assert ports[1].state == "LISTEN"


def test_parse_ps_sorts_and_limits() -> None:
    processes = parse_ps(PS_OUTPUT, limit=2)
    assert len(processes) == 2
    assert processes[0].pid == 100
    assert processes[0].command == "python worker.py"
    assert processes[1].pid == 999


def test_parse_services() -> None:
    services = parse_services(SERVICES_OUTPUT)
    assert [service.name for service in services] == ["ssh.service", "nginx.service"]
    assert services[0].active == "active"
    assert services[0].description == "OpenBSD Secure Shell server"


def test_parse_passwd_and_group() -> None:
    entries = parse_passwd(PASSWD)
    assert entries == (
        ("root", 0, 0, "/root", "/bin/bash"),
        ("ubuntu", 1000, 1000, "/home/ubuntu", "/bin/bash"),
    )
    names, memberships = parse_group(GROUP)
    assert names[1000] == "ubuntu"
    assert memberships["ubuntu"] == ("sudo", "adm")
    assert memberships["alice"] == ("adm",)


def test_collect_users(tmp_path: Path) -> None:
    passwd = tmp_path / "passwd"
    passwd.write_text(PASSWD, encoding="utf-8")
    group = tmp_path / "group"
    group.write_text(GROUP, encoding="utf-8")

    users = collect_users(passwd, group)
    assert [user.name for user in users] == ["root", "ubuntu"]
    ubuntu = users[1]
    assert ubuntu.group == "ubuntu"
    assert ubuntu.supplemental_groups == ("sudo", "adm")


def test_parse_upgradable() -> None:
    text = "3 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n"
    assert parse_upgradable(text) == 3
    assert parse_upgradable("Nothing to do") == 0

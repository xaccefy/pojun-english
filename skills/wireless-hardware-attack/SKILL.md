---
name: wireless-hardware-attack
description: Use when the target includes WiFi/Bluetooth/wireless devices, IoT or physical hardware — the basic paths for wireless recon, WPA attack paths, Bluetooth/BLE, firmware extraction and hardware interface testing.
tags:
  cwe: [CWE-321, CWE-798, CWE-1188]
  attack: [T1465, T1557]
  class: [wireless, hardware, iot, firmware]
---

# Wireless and Hardware Cheat Sheet

## WiFi

- Recon: `iw dev`, `airodump-ng <iface>` (inspect APs/clients/encryption type);
- WPA/WPA2: capture the 4-way handshake → `aircrack-ng -w rockyou.txt cap`; WPS: `reaver` (get authorization first!);
- Enterprise (802.1X): EAP downgrade / evil twin are high-risk tests — only during an explicitly authorized exercise;
- Verdict: only counts as L3 when you obtain a plaintext credential or gain internal network access.

## Bluetooth / BLE

- `bluetoothctl scan on`, `hcitool lescan`;
- BLE characteristic read/write: `gatttool -b <mac> --char-read`; a writable characteristic without auth → device control;
- Verify pairing mode / default PIN (0000/1234).

## IoT / Firmware

- Firmware extraction: vendor download / capture the upgrade endpoint / read the flash (`binwalk -e firmware.bin`);
- After unpacking look for: `/etc/shadow`, hard-coded keys, debug interfaces (telnet/uart), `squashfs-root/www`;
- Emulation: boot the firmware with `firmadyne`/`qemu` (use with care, isolated network);
- Hardware: identify UART/JTAG pins (`picocom -b 115200 /dev/ttyUSB0`); read-only first.

## Boundaries

- Wireless attacks interfere with others; only during an explicitly authorized exercise/test window;
- Do not interfere with production wireless, do not run deauth floods;
- Test firmware/hardware in an isolated environment, never on the production network.

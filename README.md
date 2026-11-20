# Elisha

*Freely you have received, freely give.* (Matthew 10:8)

Named for the prophet who refused payment for what God gave freely (2 Kings 5). Radio programming should not need a login, a subscription, or someone else's server.

A free, local radio programming tool for Meshtastic and MeshCore. It opens a simple web page on your own computer (127.0.0.1 only) and runs the official command line tools for you. No account, no cloud, no internet needed once it is set up.

## Windows, easiest way

Double click `Start Elisha.bat`. The first time it installs the radio tools (needs internet once), then it starts Elisha and opens your browser. After that it starts right up, no internet needed.

## Quick start

    git clone https://github.com/JonnyNeutron/elisha
    cd elisha
    pip install -r requirements.txt
    python3 elisha.py

Or install it as a command:

    pip install .
    elisha

## Install (do this once, while you have internet)

You need Python 3.10 or newer.

    pip install meshtastic meshcore-cli "esptool>=5"

To carry the install with you for a no internet situation, grab the packages ahead of time:

    pip download -d wheels meshtastic meshcore-cli "esptool>=5"

Later, on an offline machine:

    pip install --no-index --find-links wheels meshtastic meshcore-cli "esptool>=5"

Also download the firmware files you might need (from the Meshtastic and MeshCore release pages) and keep them somewhere safe.

## Run

    python3 elisha.py

It prints a link with a token in it and opens your browser. The token is saved in your data folder, so the same link keeps working after a restart and you can bookmark it. If you ever see a token error, copy the full link from the terminal. Pick Meshtastic, MeshCore, or MC Repeater at the top, pick the serial port, and go.
## What it does

Meshtastic: read config and node list, set names, region, modem preset, role, TX power, fixed position, edit channels and keys, add or delete channels, join from a channel URL, share URL and QR, back up and restore full config (YAML), reboot, clear node list, factory reset, any `--set` field.

MeshCore (companion radios): read device info, set name, radio parameters, TX power, position, manage channels (hashtag channels or 32 hex keys), advert, clock sync, back up and restore as a script, export and import the identity key.

MeshCore repeaters: a raw serial console at 115200 baud. Quick buttons send `ver`, `get name`, `get radio`, `clock`. Anything the repeater CLI understands can be typed in.

Firmware: keep a local firmware library. Flash ESP32 boards with esptool (full image at 0x0 or app only at 0x10000), erase flash, check chip, and flash nRF52 boards (RAK4631, T-Echo and similar) by copying a .uf2 to the bootloader drive.

## Your data

Everything lives in `~/Elisha` (override with `ELISHA_HOME`):

- `backups/` config backups and key files, saved read only to your user
- `firmware/` firmware you drop in
- `audit.log` every command that was run, with keys hidden

Backups contain your channel keys. Treat them like passwords.

## Safety notes

- Only listens on 127.0.0.1 and requires the token from the printed link.
- Commands run without a shell, and inputs are checked before they reach the tools.
- Keys are hidden in the on screen output by default (untick "hide keys" to see them).
- Factory reset, flash erase and key import make you type a confirmation word.

## Honest limits

This was built and tested without a radio attached. The web page, the input checks, command building, backups and the error handling were all tested, but I could not run it against real hardware. Expect to find a rough edge or two on first use, especially around:

- MeshCore output formats (the backup reads the device info and channel list that meshcore-cli prints)
- MeshCore repeater CLI command names, since that console just passes your text through
- Windows and macOS drive and port detection for the UF2 step

Test on a spare radio before you trust it on your main node. If something fails, the output panel shows the exact command that ran, so you can repeat it by hand.

## Env switches

- `ELISHA_DRYRUN=1` builds and shows commands without running anything. Good for checking what it would do.
- `--port 9000` picks the web port. `--no-browser` skips opening a window.

## Tests

    python3 -m unittest discover -s tests -v

The tests run in dry mode. They need no radio and none of the radio tools installed.

## Contributing

Issues and pull requests are welcome, especially hardware test reports. Say which board, which firmware version, and paste the command line the output panel showed.

## Disclaimer

Not affiliated with or endorsed by the Meshtastic or MeshCore projects. It is a front end for their published command line tools. You are responsible for transmitting legally in your region. Use at your own risk, and back up a radio before changing it.

## License

MIT, see LICENSE.

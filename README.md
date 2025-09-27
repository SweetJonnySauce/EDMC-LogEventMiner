# EDMC-LogEventMiner

EDMC-LogEventMiner is a lightweight [Elite Dangerous Market Connector](https://github.com/EDCD/EDMarketConnector) plugin that mirrors every incoming journal entry to its own log file while letting you exclude noisy events.

## Features

- Creates a dedicated journal log so you can analyse events without wading through EDMC's main log.
- Configure include/exclude lists to isolate the events that matter for your workflow.
- Forward entries to the EDMC log and add custom markers directly from the preferences panel.
- Manage multiple logging “profiles”, each with its own filters and optional profile-based log filename.
- Adjust log location on the fly and optionally append the active profile name to the log file.

## Installation

1. Download or clone this repository.
2. Copy the `EDMC-LogEventMiner` folder into your EDMC plugins directory (`File > Settings > Plugins > Open`).
3. Restart EDMC so it discovers the new plugin.

## Usage

With EDMC running, every journal event from the game is echoed to both the main EDMC log and `EDMC-LogEventMiner.log` inside EDMC's log directory. Typical paths:
- Windows: `%LOCALAPPDATA%\EDMarketConnector\logs\`
- macOS: `~/Library/Application Support/EDMarketConnector/logs/`
- Linux: `~/.config/EDMarketConnector/logs/`

### Excluding Events

1. In EDMC, open `File > Settings > Plugins` and select **EDMC-LogEventMiner**.
2. Enter the event names you want to ignore (one per line, or separated by commas/semicolons).
3. Click **Save**. Changes take effect immediately.

Any event listed there—such as `Fileheader` or `Music`—will be skipped in the dedicated log.

## Versioning

Before you cut a release:
- Update the version string in the `VERSION` file.
- Reflect the changes in `CHANGELOG.md` under a new dated heading.
- Run `python3 -m compileall load.py` (or your preferred test suite) to confirm the build is healthy.
- Commit your changes with a message such as `chore: release vX.Y.Z`.

TODO:
- Make log file unique to profile.
- Take "full" off the payload label
- add log rotation capabilities with options. 
- add auto updating capabilities

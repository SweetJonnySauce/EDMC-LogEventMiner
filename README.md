# EDMC-LogEventMiner

EDMC-LogEventMiner is a lightweight [Elite Dangerous Market Connector](https://github.com/EDCD/EDMarketConnector) plugin that mirrors every incoming journal entry to its own log file while letting you exclude noisy events.

## Installation

1. Download or clone this repository.
2. Copy the `TestEventLogger` folder into your EDMC plugins directory (`File > Settings > Plugins > Open`).
3. Restart EDMC so it discovers the new plugin.

## Usage

With EDMC running, every journal event from the game is echoed to both the main EDMC log and `TestEventLogger.log` inside EDMC's log directory. Typical paths:
- Windows: `%LOCALAPPDATA%\EDMarketConnector\logs\`
- macOS: `~/Library/Application Support/EDMarketConnector/logs/`
- Linux: `~/.config/EDMarketConnector/logs/`

### Excluding Events

1. In EDMC, open `File > Settings > Plugins` and select **Test Event Logger**.
2. Enter the event names you want to ignore (one per line, or separated by commas/semicolons).
3. Click **Save**. Changes take effect immediately.

Any event listed there—such as `Fileheader` or `Music`—will be skipped in the dedicated log.

TODO:
- Rename repo
- Make log file unique to profile.

# EDMC-LogEventMiner

[![Github All Releases](https://img.shields.io/github/downloads/SweetJonnySauce/EDMC-LogEventMiner/total.svg)](https://github.com/SweetJonnySauce/EDMC-LogEventMiner/releases/latest)

EDMC-LogEventMiner is a lightweight [Elite Dangerous Market Connector](https://github.com/EDCD/EDMarketConnector) plugin that mirrors every incoming journal entry to its own log file while letting you exclude noisy events.

This plugin is not meant to enhance youre Elite Dangerous gameplay, rather is for those that are interesting in knowing more about the journal event whether it's for curiosity or developing your own plugin. 

## Features

- Creates a dedicated journal log so you can analyse events without wading through EDMC's main log.
- Configure include/exclude lists to isolate the events that matter for your workflow.
- Forward entries to the EDMC log if you want them in the main log.
- Add custom markers to the log file directly from the preferences panel.
- Manage multiple logging “profiles”, each with its own filters and optional profile-based log filename.
- Adjust log location on the fly and optionally append the active profile name to the log file.
- Rotate log files automatically with configurable thresholds per profile.

## Installation

1. Download the latest release.
2. Copy the `EDMC-LogEventMiner` folder into your EDMC plugins directory (`File > Settings > Plugins > Open`).
3. Restart EDMC so it discovers the new plugin.

## Usage

With EDMC running, every journal event from the game is echoed to both the main EDMC log and `EDMC-LogEventMiner.log` inside EDMC's log directory. Typical paths:
- Windows: `%LOCALAPPDATA%\EDMarketConnector\logs\`
- macOS: `~/Library/Application Support/EDMarketConnector/logs/`
- Linux: `~/.config/EDMarketConnector/logs/`

## TODO:
- add auto updating capabilities

## Disclaimer:
I wasn't expecting to write this. All I wanted to do was to mine some specific journal events for a different
project. I started making this via vibe coding with Codex and then I wanted to see how far I could go. 
I did not touch any bit of code in load.py by hand as I wanted to see just what was possible. You are free to pick this apart and I welcome the feedback. My intent though is to keep this 100% vibe coded.

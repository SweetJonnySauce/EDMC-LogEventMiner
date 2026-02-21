# EDMC-LogEventMiner

[![Github All Releases](https://img.shields.io/github/downloads/SweetJonnySauce/EDMC-LogEventMiner/total.svg)](https://github.com/SweetJonnySauce/EDMC-LogEventMiner/releases/latest)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-clean-brightgreen.svg)](https://www.virustotal.com/gui/url/a86d46dc81d50619493f3e2a246a0c3ba3aa676a55b3e6c03a873df317f6d3a1?nocache=1)

EDMC-LogEventMiner is a lightweight [Elite Dangerous Market Connector](https://github.com/EDCD/EDMarketConnector) plugin that mirrors every incoming journal entry to its own log file while letting you exclude noisy events.

This plugin is not meant to enhance youre Elite Dangerous gameplay, rather is for those that are interesting in knowing more about the journal event whether it's for curiosity or developing your own plugin. 

Display events in-game using [EDMCModernOverlay](https://github.com/SweetJonnySauce/EDMCModernOverlay)

<img width="316" height="274" alt="image" src="https://github.com/user-attachments/assets/19ffd871-a55b-48b9-80f6-fb5916d9127c" />


## Features

- Creates a dedicated journal log so you can analyse events without wading through EDMC's main log.
- Configure include/exclude lists to isolate the events that matter for your workflow.
- Forward entries to the EDMC log if you want them in the main log.
- Add custom markers to the log file directly from the preferences panel.
- Manage multiple logging “profiles”, each with its own filters and optional profile-based log filename.
- Adjust log location on the fly and optionally append the active profile name to the log file.
- Rotate log files automatically with configurable thresholds per profile.
- Overlay support using [EDMCModernOverlay](https://github.com/SweetJonnySauce/EDMCModernOverlay)

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
Warning: Here be AI slop (most likely). This was my first real attempt at coding a plugin using AI (Codex). Critisicm and feedback is welcome but I probably won't do much to overcome any AI mess that may be here.

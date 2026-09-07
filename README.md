# EDMC-LogEventMiner

[![Github All Releases](https://img.shields.io/github/downloads/SweetJonnySauce/EDMC-LogEventMiner/total.svg)](https://github.com/SweetJonnySauce/EDMC-LogEventMiner/releases/latest)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-clean-brightgreen.svg)](https://www.virustotal.com/gui/url/a86d46dc81d50619493f3e2a246a0c3ba3aa676a55b3e6c03a873df317f6d3a1?nocache=1)
[![AILevel](https://img.shields.io/badge/Level-4.%20Local%20Autonomous%20Agent-purple?logo=openaigym&logoColor=white&link=https%3A%2F%2Feclipsesource.com%2Fblogs%2F2025%2F06%2F26%2Fai-coding-spectrum-levels-of-assistance%2F)]([![AILevel](https://img.shields.io/badge/Level-4.%20Local%20Autonomous%20Agent-purple?logo=openaigym&logoColor=white&link=https%3A%2F%2Feclipsesource.com%2Fblogs%2F2025%2F06%2F26%2Fai-coding-spectrum-levels-of-assistance%2F
)

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
- Optional status-change logging sourced from EDMC `dashboard_entry()` updates.
- Dedicated `Status` settings tab with per-status tracking checkboxes (including all `GuiFocus*` constants), profile-scoped settings, and status overlay controls.
- Separate status overlay group that renders current tracked status values (including mapped + raw `GuiFocus`).
- Resizable CAPI Monitor window for inspecting incoming commander and fleet-carrier data.

## Installation

1. Download the latest release.
2. Copy the `EDMC-LogEventMiner` folder into your EDMC plugins directory (`File > Settings > Plugins > Open`).
3. Restart EDMC so it discovers the new plugin.

## Usage

With EDMC running, journal events are written to `EDMC-LogEventMiner.log` inside EDMC's log directory. Forwarding to the main EDMC log is optional. Typical paths:
- Windows: `%LOCALAPPDATA%\EDMarketConnector\logs\`
- macOS: `~/Library/Application Support/EDMarketConnector/logs/`
- Linux: `~/.config/EDMarketConnector/logs/`

### CAPI Monitor

Open EDMC's settings, select this plugin's **Settings** tab, and click
**CAPI Monitor**. A resizable, terminal-style window displays incoming CAPI
callbacks as formatted JSON, labelled with the receipt time (UTC), callback name,
source host, and beta flag where supplied. Unknown/new fields are included.

Use EDMC's **Update** button to request fresh commander data. The monitor listens
to Live/Beta, Legacy, and fleet-carrier updates that EDMC supplies; it does not
fetch data itself or replay updates received before opening. Fleet-carrier data
appears when EDMC delivers its separate callback.

The window stays open when settings closes. Scroll to inspect previous output;
scroll back to the bottom to follow incoming updates. Text can be selected and
copied. History is held in memory while open, limited to two million characters
with a visible notice when older output is discarded. **Close** or the window's
close control stops monitoring and clears the history. Clicking **CAPI Monitor**
again raises the existing window or opens a new session.

## TODO:
- add auto updating capabilities

## Disclaimer:
Warning: Here be AI slop (most likely). This was my first real attempt at coding a plugin using AI (Codex). Critisicm and feedback is welcome but I probably won't do much to overcome any AI mess that may be here.

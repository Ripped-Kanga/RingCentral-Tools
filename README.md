# RingCentral-Tools

A modular, CLI-based toolkit for auditing and health-checking RingCentral instances via the RingCentral REST API. All API calls are **read-only GET requests** — no data is modified.

---

## Overview

RingCentral-Tools is designed to grow into a full suite of auditing and reporting modules for RingCentral administrators. Each module is self-contained and registered in a central menu, making it easy to add new capabilities over time without touching existing functionality.

On launch, the tool authenticates via OAuth, verifies connectivity, and presents an interactive menu to select which module to run.

---

## Current Modules

### User Extension Audit
Performs a comprehensive audit of all extensions on a RingCentral account and exports results to CSV.

**Features:**
- Filter extensions by type (User, Call Queue, IVR Menu, Announcement, Voicemail, etc.), status, extension number, or email
- Select individual fields to export — only the data you need
- Exports a **User/Extension CSV** covering:
  - ID, Name, Extension Number, Direct Number, Status, Type, Site
  - Company, Department, Job Title, Email
  - Administrator status, Assigned Role, Setup Wizard State
  - DND / Presence status
  - Business Hours forwarding destination
  - After Hours forwarding destination
  - Device Name, Model, Serial, and Status
- Exports a **Call Queue CSV** (when Call Queue type is selected) covering:
  - Queue Name and Extension Number
  - Each member's name, extension, and queue acceptance status
  - Hold-time expiration forwarding destination and type
- Writes incrementally — progress is not lost if interrupted
- Automatically respects API rate limits

Results are saved to `AuditResults/` with a datestamp in the filename.

---

## Installation

### Clone the repository
```bash
git clone https://github.com/Ripped-Kanga/RingCentral-Tools.git
cd RingCentral-Tools
```

### Install dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

### Optional arguments

| Argument | Description |
|---|---|
| `--client_id` | Provide the OAuth Client ID at runtime |
| `--client_secret` | Provide the OAuth Client Secret at runtime |
| `--clear-creds` | Clear saved credentials and force re-authentication |

If `--client_id` and `--client_secret` are not provided, the tool will prompt for them interactively.

### Example
```bash
python main.py --client_id YOUR_CLIENT_ID --client_secret YOUR_CLIENT_SECRET
```

---

## Adding New Modules

New modules can be added by:

1. Creating a new file under `modules/` with a `run(client)` function
2. Registering it in the `MODULE_REGISTRY` dict in `main.py`

```python
# main.py
from modules import my_new_module

MODULE_REGISTRY = {
    "User Extension Audit": user_audit,
    "My New Module":        my_new_module,  # add here
}
```

The module will automatically appear in the interactive menu — no other changes required.

---

## Notes

- To exit at any time, press **CTRL+C**
- Output CSV files are stored in the `AuditResults/` directory
- Selecting more fields during an audit increases runtime and API call volume; the tool will automatically pause if rate limits are hit

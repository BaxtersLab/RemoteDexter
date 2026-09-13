# Bootstrap ICO Module

Self-contained Windows bootstrap that creates Desktop, Start Menu, and
optional Startup shortcuts for **RemoteDexter**.  No admin rights, no
installer, no registry edits — the Git pull *is* the installation.

## Contents

| File                   | Purpose                                                         |
|------------------------|-----------------------------------------------------------------|
| `bootstrap.ico`        | Multi-resolution Windows icon (16/32/48/64/128/256 px)          |
| `install_shortcut.bat` | Interactive/scriptable shortcut creator + first-launch           |
| `create_shortcut.vbs`  | VBScript helper — creates `.lnk` files (called by the .bat)     |
| `README.md`            | This file                                                       |

## Quick Start

```
cd windows\bootstrap
install_shortcut.bat
```

The script will:

1. Create a **Desktop** shortcut named `RemoteDexter.lnk` → `windows\run.bat`
2. Create a **Start Menu** shortcut named `RemoteDexter.lnk`
3. Prompt: *"Do you want RemoteDexter to auto-start when Windows boots? (Y/N):"*
   - **Y** → creates a Startup shortcut (auto-run on boot)
   - **N** → skips it
4. Launch the host once through `run.bat`, then exit

All shortcuts use `bootstrap.ico` and set the working directory to the
folder containing `run.bat` (which starts `host_app.exe` beside it).

## Requirements

- Windows 10 / 11 (cscript.exe ships with every Windows installation)
- No admin rights required
- No Python, no PowerShell, no third-party dependencies

## How It Works

`install_shortcut.bat` calls `create_shortcut.vbs` via `cscript //nologo`.
The VBScript uses the `WScript.Shell` COM object to create standard `.lnk`
shortcut files — this is the native Windows mechanism that requires no admin
privileges, no SDK, and no third-party tools.  `bootstrap.ico` is embedded
in each shortcut so Windows Explorer displays the correct icon.

Windows batch scripts cannot create `.lnk` files directly, which is why the
VBScript helper exists as a separate file.

## Path Expectations

```
RemoteDexter/
├── windows/
│   ├── run.bat                     ← shortcut target
│   ├── host_app.exe                ← started by run.bat (build output)
│   └── bootstrap/
│       ├── bootstrap.ico           ← multi-res icon
│       ├── install_shortcut.bat    ← run this
│       ├── create_shortcut.vbs     ← .lnk helper (called by .bat)
│       └── README.md
└── image artifacts/
    └── RDicon.png                  ← icon source PNG
```

## Regenerating the Icon

If the source PNG at `image artifacts\RDicon.png` is updated, regenerate
the ICO with Python + Pillow:

```
pip install Pillow
python -c "from PIL import Image; Image.open(r'..\..\image artifacts\RDicon.png').convert('RGBA').save('bootstrap.ico', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"
```

This is only needed when the source artwork changes — the committed
`bootstrap.ico` is ready to use as-is.

# Microsoft Store package

This directory contains the MSIX packaging path for the AntiOS GUI.

The Store package is a submission artifact; building it locally does not mean that Microsoft has certified or published that build.

## Current identity

- Package/Identity/Name: DargonsITP.AntiOS
- Package/Identity/Publisher: CN=D0D34602-FED2-4FE0-B705-18B9041C45F3
- Publisher display name: DargonITP
- Store ID: 9P7V8BKW2KG9
- Store URL: https://apps.microsoft.com/detail/9P7V8BKW2KG9

These values must match Partner Center.

## Build

The repository workflow is .github/workflows/store.yml. It builds the GUI and an unsigned MSIX suitable for Partner Center submission.

The default package version for the current line is 3.0.2.0.

Manual build:

    python scripts/build-icons.py
    pyinstaller --clean --noconfirm --onedir --contents-directory _gui --uac-admin --icon .\build\icons\app_main.ico --add-data "antios/assets/icons;antios/assets/icons" --version-file release/windows-gui-version.txt --windowed --name AntiOS-GUI antios_gui_entry.py

    .\scripts\build-store-msix.ps1 -IdentityName "DargonsITP.AntiOS" -Publisher "CN=D0D34602-FED2-4FE0-B705-18B9041C45F3" -PublisherDisplayName "DargonITP" -PackageVersion "3.0.2.0"

Output: store-output\AntiOS.msix.

The local build script does not production-sign the package. Accepted Store submissions are signed by Microsoft through the Store distribution process.

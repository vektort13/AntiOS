# AntiOS Microsoft Store package

The Store edition packages the **AntiOS GUI**, including on-demand antivirus scans and explicitly confirmed quarantine/restore actions.

It does not package the advanced CLI, so Microsoft Store users receive the antivirus and health/privacy dashboard without the CLI's administrator-only metadata write commands. The GUI requests UAC elevation at startup; the manifest declares the restricted `allowElevation` capability. Microsoft must approve that capability before Store publication. Protection policy is unchanged. The Store identity remains reserved; package generation is not Store certification.

## Why MSIX

Microsoft Store distribution gives AntiOS:

- a trusted Microsoft signature after certification;
- clean install/uninstall;
- Store-managed updates;
- package identity;
- no first-download SmartScreen warning for the Store-delivered package.

## Reserved Partner Center identity

AntiOS now has a reserved Microsoft Store identity:

- Package/Identity/Name: `DargonsITP.AntiOS`
- Package/Identity/Publisher: `CN=D0D34602-FED2-4FE0-B705-18B9041C45F3`
- Publisher display name: `DargonITP`
- Store ID: `9P7V8BKW2KG9`
- Store URL: https://apps.microsoft.com/detail/9P7V8BKW2KG9

These values must match the Partner Center product identity exactly.

## Build

First build the GUI executable:

```powershell
pyinstaller --clean --noconfirm --onedir --contents-directory _gui --uac-admin --version-file release/windows-gui-version.txt --windowed --name AntiOS-GUI antios_gui_entry.py
```

Then:

```powershell
.\scripts\build-store-msix.ps1 `
  -IdentityName "DargonsITP.AntiOS" `
  -Publisher "CN=D0D34602-FED2-4FE0-B705-18B9041C45F3" `
  -PublisherDisplayName "DargonITP" `
  -PackageVersion "2.0.19.0"
```

Output:

```text
store-output\AntiOS.msix
```

The fourth version component is kept at `.0` for Store submission.

The package is intentionally not production-signed by this script. Microsoft Store signs accepted submissions itself.

## CI

`.github/workflows/store-msix.yml` validates that the Store package can be generated.

Pull requests and manual runs now default to the reserved AntiOS Partner Center identity. The workflow still exposes identity inputs so the package can be rebuilt against a different reserved identity if needed.

The generated artifact is an input for Partner Center, not a substitute for Store certification.

# AntiOS

Change Windows and hardware identifiers so that change system fingerprint.

### You need to install at least Python 3.6, last version preferred

https://www.python.org/downloads/

!!!ATTENTION!!!
* When you install Python, make sure that you select "Custom" installation mode and check "Install for all users" 
* On the current stage this application does not back up your system initial state, run it in the virtual machine not to damage your host system

## How to use:

Run `python.exe generate_fingerprint.py --help` for available options.

If you are not comfortable with the command-line, simply start the batch file `START.bat` with Administrator privileges

List of changed identificators:

* Username
* Hostname
* Current windows build
* Current windows build number
* Windows build lab
* BuildLabEx
* BuildGuid
* CryptoMachineGuid
* DeviceGuid
* CKCL Guid
* HardwareProfileGuid
* WMIGuid
* EDGE Guid
* InstallDate
* ProductID
* WindowsUpdateClientID
* IE ProductID
* IE KBNumber
* IE Install date
* VolumeID
* MACadress
* HardwareGUID

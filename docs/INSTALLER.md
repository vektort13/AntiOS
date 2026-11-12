# Windows installation

Use the latest published AntiOS installer for normal Windows deployment.

## Public behavior

- installs the application and required product components;
- supports upgrade and uninstall;
- prepares protection features according to the selected product configuration;
- attempts to preserve user choices across compatible upgrades;
- reports installation or repair failures instead of silently claiming success.

## Internal design

Exact installation directories, service/task names, ACL changes, bootstrap order, repair snapshots, rollback sequence, upgrade staging layout, updater handoff and postcondition checks are intentionally omitted from public documentation.

Those details are maintained in private engineering documentation.

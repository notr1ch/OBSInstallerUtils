# OBSInstallerUtils
This library is designed to be used with NSIS (Unicode version). It provides the following features:

```
OBSInstallerUtils::IsProcessRunning
OBSInstallerUtils::IsDLLLoaded
OBSInstallerUtils::AddInUseFileCheck
OBSInstallerUtils::GetAppNameForInUseFiles
OBSInstallerUtils::KillProcess
```

AddInUseFileCheck expects a full path. Can be called multiple times. Afterwards, call GetAppNameForInUseFiles and $R0 will be a nicely formatted list of applications that are using the specified files.

KillProcess takes a substring match on the full path.

Other functions sets $R0 to 1 if true.

Example usage: https://github.com/jp9000/obs-studio/blob/master/UI/installer/mp-installer.nsi

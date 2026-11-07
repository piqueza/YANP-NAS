# SPDX-License-Identifier: GPL-2.0-only
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from agent.snapshot_mount_package import LINUX,WINDOWS

CONNECTION={'host':'192.168.1.2','share':'yanp-view-'+'a'*32,'username':'ynpview_'+'a'*16,'password':'test-private-package'}

class PackageScriptTests(unittest.TestCase):
    def test_linux_mount_uses_private_callback_credentials_without_saving_password(self):
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/'mount.py';script.write_text(LINUX)
            script.with_name('connection.json').write_text(json.dumps(CONNECTION))
            pending=[];operation=Mock();file=Mock()
            def start(flags,op,cancel,callback,unmount):
                callback_credentials=op.connect.call_args.args[1]
                callback_credentials(op,'password','','',0)
                pending.append(lambda:callback(file,None,unmount))
            file.mount_enclosing_volume.side_effect=start
            gio=SimpleNamespace(File=SimpleNamespace(new_for_uri=Mock(return_value=file)),MountOperation=Mock(return_value=operation),PasswordSave=SimpleNamespace(NEVER=0),MountOperationResult=SimpleNamespace(HANDLED=0),MountMountFlags=SimpleNamespace(NONE=0),AppInfo=SimpleNamespace(launch_default_for_uri=Mock()))
            glib=SimpleNamespace(MainLoop=lambda:SimpleNamespace(run=lambda:pending.pop()(),quit=lambda:None),Error=type('FakeGError',(Exception,),{}))
            gi=ModuleType('gi');gi.require_version=Mock()
            repository=ModuleType('gi.repository');repository.Gio=gio;repository.GLib=glib
            with patch.dict(sys.modules,{'gi':gi,'gi.repository':repository}),patch.object(sys,'argv',[str(script)]),patch('os.geteuid',return_value=1000),patch('builtins.print'):
                runpy.run_path(str(script),run_name='__main__')
            operation.set_password.assert_called_once_with(CONNECTION['password']);operation.set_password_save.assert_called_once_with(0)
            file.mount_enclosing_volume_finish.assert_called_once()
            gio.AppInfo.launch_default_for_uri.assert_called_once_with('smb://'+CONNECTION['username']+'@192.168.1.2/'+CONNECTION['share'],None)

    @unittest.skipUnless(shutil.which('pwsh'),'PowerShell needed')
    def test_windows_script_parses_and_maps_without_removing_unrelated_drives(self):
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/'mount.ps1';script.write_text(WINDOWS)
            script.with_name('connection.json').write_text(json.dumps(CONNECTION))
            # Windows identity APIs are absent on Linux. Stub only this platform
            # boundary; run the generated mapping/credential code in PowerShell.
            shim=WINDOWS.replace("$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())","$principal = [pscustomobject]@{}; $principal | Add-Member ScriptMethod IsInRole { return $false }")
            mocked=Path(folder)/'mapping.ps1';mocked.write_text(shim)
            harness=r'''
param($Script,$Original)
$tokens=$null;$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile($Original,[ref]$tokens,[ref]$errors) > $null
if($errors.Count){throw ($errors | Out-String)}
function Get-SmbMapping {param($LocalPath,$ErrorAction) if(-not $LocalPath){ [pscustomobject]@{RemotePath='\\other\share';LocalPath='Y:'} }}
function Get-PSDrive {param($Name,$ErrorAction) if($Name -eq 'Z'){[pscustomobject]@{Name='Z'}}}
function New-PSDrive {param($Name,$PSProvider,$Root,$Credential,[switch]$Persist,$Scope)
 if($Name -ne 'X' -or $PSProvider -ne 'FileSystem' -or -not $Persist -or $Scope -ne 'Global'){throw 'Bad mapping flags'}
 if($Root -ne ('\\192.168.1.2\yanp-view-' + ('a'*32))){throw 'Wrong share'}
 if($Credential.GetNetworkCredential().Password -ne 'test-private-package'){throw 'Credential mismatch'}
 $global:created=$true
}
function Remove-SmbMapping {throw 'Must not disconnect other mappings'}
function Start-Process {param($FilePath,$ArgumentList) if($FilePath -ne 'explorer.exe' -or $ArgumentList -ne 'X:\'){throw 'Wrong explorer target'}}
& $Script
if(-not $global:created){throw 'Mapping not created'}
'''
            # Model Y: as occupied in both providers, as it is on Windows.
            harness=harness.replace("if($Name -eq 'Z')","if($Name -in @('Z','Y'))")
            test=Path(folder)/'test.ps1';test.write_text(harness)
            result=subprocess.run(['pwsh','-NoLogo','-NoProfile','-File',str(test),str(mocked),str(script)],text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)

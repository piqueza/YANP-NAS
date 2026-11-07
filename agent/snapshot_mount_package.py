# SPDX-License-Identifier: GPL-2.0-only
"""Small, credential-bearing recovery packages; never persisted on the NAS."""
import base64
import io
import json
import zipfile

LINUX = '''#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run in your normal Linux desktop session: python3 mount.py [--unmount]."""
import json
from pathlib import Path
import sys
from urllib.parse import quote
try:
    import gi
    gi.require_version('Gio', '2.0')
    from gi.repository import Gio, GLib
except (ImportError, ValueError):
    sys.exit('Desktop SMB support is required: Python 3 PyGObject (python3-gi) and GVfs SMB backend (gvfs-backends on Debian/Ubuntu). Ask your administrator to install these, then run as your normal desktop user.')
import os
if os.geteuid() == 0:
    sys.exit('Run as your normal desktop user, not root.')
if sys.argv[1:] not in ([], ['--unmount']):
    sys.exit('Usage: python3 mount.py [--unmount]')
config = json.loads(Path(__file__).with_name('connection.json').read_text())
host = config['host']
if ':' in host: host = '[' + host + ']'
uri = 'smb://' + quote(config['username'], safe='') + '@' + host + '/' + config['share']
file = Gio.File.new_for_uri(uri)
loop = GLib.MainLoop()
errors = []
operation = Gio.MountOperation()
def credentials(op, message, default_user, default_domain, flags):
    op.set_username(config['username'])
    op.set_domain('WORKGROUP')
    op.set_password(config['password'])
    op.set_password_save(Gio.PasswordSave.NEVER)
    op.reply(Gio.MountOperationResult.HANDLED)
operation.connect('ask-password', credentials)
def complete(obj, result, unmount):
    try:
        if unmount:
            obj.unmount_with_operation_finish(result)
            print('Disconnected from this snapshot on this computer. The NAS share remains open until closed in YANP or on the original client.')
        else:
            try: obj.mount_enclosing_volume_finish(result)
            except GLib.Error as error:
                if not error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.ALREADY_MOUNTED): raise
            print('Read-only snapshot mounted. File explorer location: ' + uri)
            Gio.AppInfo.launch_default_for_uri(uri, None)
    except Exception as error:
        errors.append(str(error))
    finally: loop.quit()
try:
    if '--unmount' in sys.argv:
        mount = file.find_enclosing_mount(None)
        if mount.get_root().get_uri().rstrip('/') != file.get_uri().rstrip('/'):
            sys.exit('Refusing to unmount a different share.')
        mount.unmount_with_operation(Gio.MountUnmountFlags.NONE, operation, None, complete, True)
    else:
        file.mount_enclosing_volume(Gio.MountMountFlags.NONE, operation, None, complete, False)
    loop.run()
except GLib.Error as error:
    sys.exit(str(error))
if errors: sys.exit(errors[0])
'''

WINDOWS = r'''# SPDX-License-Identifier: GPL-2.0-only
# Run in a normal, non-administrator Windows PowerShell session.
param([switch]$Unmount)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'connection.json') -Raw | ConvertFrom-Json
$server = [string]$config.host
if ($server.Contains(':')) { throw 'For Windows SMB, use a NAS IPv4 address or DNS hostname instead of an IPv6 literal.' }
$remote = '\\' + $server + '\' + $config.share
$existing = @(Get-SmbMapping | Where-Object { $_.RemotePath -eq $remote })
if ($Unmount) {
    foreach ($mapping in $existing) {
        Remove-SmbMapping -LocalPath $mapping.LocalPath -Force -UpdateProfile
    }
    Write-Host 'Disconnected this snapshot on this computer. Close the share in YANP when everyone is finished.'
    exit
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in a normal PowerShell window so the drive is visible to your normal File Explorer session.'
}
if ($existing.Count -gt 0) {
    $location = $existing[0].LocalPath + '\'
} else {
    $letter = @([char[]](90..68) | Where-Object {
        -not (Get-PSDrive -Name ([string]$_) -ErrorAction SilentlyContinue) -and
        -not (Get-SmbMapping -LocalPath (([string]$_) + ':') -ErrorAction SilentlyContinue)
    }) | Select-Object -First 1
    if (-not $letter) { throw 'No available drive letter between D and Z.' }
    $password = ConvertTo-SecureString -String $config.password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential(('WORKGROUP\' + $config.username), $password)
    New-PSDrive -Name ([string]$letter) -PSProvider FileSystem -Root $remote -Credential $credential -Persist -Scope Global | Out-Null
    $location = ([string]$letter) + ':\'
}
Write-Host ('Read-only snapshot mounted at ' + $location)
Start-Process explorer.exe -ArgumentList $location
'''


def build_package(connection, platform, snapshot, lan):
    data=io.BytesIO()
    readme=f'''YANP Nas read-only snapshot recovery
Snapshot: {snapshot}
Permitted source network: {lan}

This private ZIP contains a temporary share password in connection.json. Anyone
with the package and permitted network access can read this snapshot while its
share is open. Keep the extracted folder private, do not commit or email it,
and delete it when finished. Credentials cannot be hidden from their recipient.
No administrator password or client agent secret is included.

Connect to the NAS on its permitted LAN (TCP 445). The snapshot is read-only on
the server. Copy files OUT to another location to recover them. No data is copied
merely by mounting. Closing the share in YANP or unmounting on the original agent
revokes ALL these recovery connections. Unmounting this additional device only
disconnects this device; it does not close the NAS share or resume uploads.
Only the selected snapshot tree's uploads are paused while this share is open.
The original client agent is not required on this additional computer.
'''
    if platform=='linux':
        name='mount.py';script=LINUX
        readme+='''
LINUX: extract to a private folder, open a terminal there in your normal desktop
session and run: python3 mount.py
Disconnect: python3 mount.py --unmount
Requires Python 3, PyGObject/Gio and a GVfs SMB backend (Debian/Ubuntu packages:
python3-gi and gvfs-backends). Your administrator may need to install these once.
This uses a desktop SMB/GVfs mount, not a privileged kernel CIFS mount. Browse it
in your file explorer; it may also appear under /run/user/<uid>/gvfs when the
GVfs FUSE bridge is installed. The managed original client still uses CIFS.
'''
    else:
        name='mount.ps1';script=WINDOWS
        readme+='''
WINDOWS: extract the ZIP to a private folder. Open normal Windows PowerShell
(not Run as administrator), change to that folder and run: .\\mount.ps1
Disconnect: .\\mount.ps1 -Unmount
Uses built-in Windows SMB and PowerShell tools, with an available D:-Z: drive.
If Windows marks the downloaded script as blocked, review it first, then run
Unblock-File -LiteralPath .\\mount.ps1. Your organization's execution policy may
require administrator approval; this package does not change or bypass it.
If Windows reports conflicting NAS credentials, disconnect only the conflicting
NAS connections yourself; this script never removes unrelated connections.
'''
    with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as archive:
        for filename,content in {'connection.json':json.dumps(connection,indent=2)+'\n',name:script,'README.txt':readme}.items():
            info=zipfile.ZipInfo(filename);info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,content)
    return {'filename':'yanp-snapshot-'+connection['share'].removeprefix('yanp-view-')+'-'+platform+'.zip','base64':base64.b64encode(data.getvalue()).decode()}

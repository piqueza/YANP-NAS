# SPDX-License-Identifier: GPL-2.0-only
"""Unprivileged fixed-command login shell for snapshot receiver accounts."""
import json
import os
import re
import shutil
import subprocess
import sys


def main():
    original=os.environ.get('SSH_ORIGINAL_COMMAND','')
    parts=original.split(' ')
    request=None
    if original in ('receive','list'):request={'operation':original}
    elif len(parts)==4 and parts[0]=='receive' and re.fullmatch(r'[a-f0-9]{24}',parts[1]) and re.fullmatch(r'ynp-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}',parts[2]) and re.fullmatch(r'[a-fA-F0-9-]{36}',parts[3]):
        request={'operation':'receive','source':parts[1],'snapshot':parts[2],'snapshot_uuid':parts[3]}
    elif len(parts) in (3,4) and parts[0]=='send' and re.fullmatch(r'[a-f0-9]{24}',parts[1]) and all(re.fullmatch(r'ynp-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}',s) for s in parts[2:]):
        request={'operation':'send','source':parts[1],'snapshot':parts[2]}
        if len(parts)==4:request['parent']=parts[3]
    if request is None:
        print('This account accepts only fixed snapshot receive/list/send commands; shells, SFTP and forwarding are unavailable.',file=sys.stderr)
        return 1
    command=['/usr/bin/sudo','-n','--','/usr/bin/python3','-I','/opt/yanp-nas/scripts/snapshot_receive.py']
    process=subprocess.Popen(command,stdin=subprocess.PIPE)
    try:
        process.stdin.write((json.dumps(request)+'\n').encode());process.stdin.flush()
        if request['operation']=='receive':shutil.copyfileobj(sys.stdin.buffer,process.stdin,1024*1024)
        process.stdin.close()
        return process.wait()
    except BaseException:
        process.terminate();process.wait()
        raise


if __name__=='__main__':raise SystemExit(main())

# SPDX-License-Identifier: GPL-2.0-only
"""Admin-only whole-disk clones; no arbitrary paths or command arguments."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

from .core import Error, boolean, integer, keys, require
from .erase import Eraser, active_swap_paths, md_members
from .initialize import identity, fingerprint, pinned_disk


def members(disk, nodes):
    return [n for n in nodes if n is disk or disk['path'] in n.get('physical_disks', [])]


def system_disks(nodes):
    return {p for n in nodes if any(m in ('/', '/boot', '/boot/efi', '/usr', '/var') for m in n.get('mountpoints', []))
            for p in n.get('physical_disks', [n['path']] if n.get('type') == 'disk' else [])}


def candidate_reason(disk, nodes, destination=False):
    if disk.get('type') != 'disk' or not disk.get('stable_id') or not disk.get('disk_sequence'):
        return 'A physical disk with a stable ID and kernel generation is required.'
    if not isinstance(disk.get('size'), int) or disk['size'] <= 0 or disk.get('log-sec') not in (512,1024,2048,4096):
        return 'Disk capacity or logical sector size is unavailable.'
    group=members(disk,nodes)
    system=disk['path'] in system_disks(nodes)
    if destination and (system or any(n.get('protected') for n in group)):
        return 'OS disks cannot be destinations; externally mounted disks must be unmounted.'
    if system and not destination:
        return 'Live OS disk cloning is disabled. Filesystem snapshots cannot be used as raw disk sources; use the system-state migration installer.'
    if destination and any(n.get('ro') not in (False,0) for n in group):
        return 'The destination must be writable.'
    if any(n.get('holders') is None for n in group):return 'Device use could not be verified.'
    if not system or destination:
        if any(any(n.get('mountpoints') or []) or n.get('holders') or n.get('type') not in ('disk','part') for n in group):
            return 'Unmount all partitions and detach active device mappings first.'
    return ''


def pair_fingerprint(source, target, nodes):
    entries=[{**identity(n), 'type':n.get('type'),'uuid':n.get('uuid'),'partuuid':n.get('partuuid'),
              'ptuuid':n.get('ptuuid'),'start':n.get('start'),'fstype':n.get('fstype')}
             for n in nodes if n in members(source,nodes)+members(target,nodes)]
    return hashlib.sha256(json.dumps(sorted(entries,key=lambda n:n['path']),sort_keys=True).encode()).hexdigest()


def map_progress(text, total):
    counts={s:0 for s in '+-?*/'};end=0
    for line in text.splitlines():
        fields=line.split()
        if len(fields)!=3 or fields[0].startswith('#') or fields[2] not in counts:continue
        start,size=int(fields[0],0),int(fields[1],0)
        require(start==end and size>0 and start+size<=total,'Invalid rescue map ranges')
        counts[fields[2]]+=size;end=start+size
    require(end==total,'Rescue map does not yet cover the full disk')
    return {'rescued_bytes':counts['+'],'bad_bytes':counts['-'],'remaining_bytes':total-counts['+'],
            'percent':round(100*counts['+']/total,2)}


def clone_command(source, destination, mapfile, total, sector, rescue):
    return ['ddrescue','--force','--sector-size='+str(sector),'--size='+str(total),
            '--mapfile-interval=2s',*(['--retry-passes=3'] if rescue else
            ['--no-trim','--no-scrape','--retry-passes=0']),source,destination,str(mapfile)]


class Clones:
    def __init__(self, config, devices, db, runner):
        self.config,self.devices,self.db,self.run=config,devices,db,runner

    def context(self, p):
        require(isinstance(p.get('source'),str) and isinstance(p.get('destination'),str),'Choose source and destination disks')
        nodes=self.devices.scan()['devices']
        pair=[]
        for key in ('source','destination'):
            matches=[n for n in nodes if n.get('type')=='disk' and n.get('stable_id')==p[key]]
            require(len(matches)==1,'Selected disk is no longer uniquely available')
            disk=matches[0];reason=candidate_reason(disk,nodes,key=='destination')
            require(not reason,reason);pair.append(disk)
        source,target=pair
        require(source['maj:min']!=target['maj:min'],'Source and destination must be different physical disks')
        require(target['size']>=source['size'],'Destination is smaller than the source disk')
        require(target['log-sec']==source['log-sec'],'Source and destination logical sector sizes must match')
        swap=active_swap_paths();md=md_members()
        for disk in pair:
            if disk is source and disk['path'] in system_disks(nodes):continue
            group=members(disk,nodes)
            require(not {os.path.realpath(n['path']) for n in group}&swap,'Active swap prevents cloning this disk')
            require(not {n.get('maj:min') for n in group}&md,'Assembled RAID members cannot be cloned here')
        eraser=Eraser(self.devices,self.db,self.run)
        eraser.references(members(target,nodes))
        require(not Path('/run/systemd/shutdown/scheduled').exists(),'A scheduled shutdown prevents cloning')
        return source,target,nodes

    def plan(self,p):
        keys(p,('source','destination','rescue'))
        boolean(p['rescue']);source,target,nodes=self.context(p)
        require(shutil.which('ddrescue') is not None,'Install Debian package gddrescue using the updated installer/updater')
        return {'source':identity(source),'destination':identity(target),'rescue':p['rescue'],
                'live_source':source['path'] in system_disks(nodes),'observed_at':int(time.time()),
                'fingerprint':pair_fingerprint(source,target,nodes),'confirmation':'CLONE '+target['path']}

    def publish(self,report):
        self.db.execute('UPDATE jobs SET result=%s WHERE id=%s',(json.dumps(report),self.run.job_id))

    def execute(self,p):
        keys(p,('source','destination','rescue','observed_at','fingerprint','confirmation','acknowledge_erase','acknowledge_live'))
        rescue=boolean(p['rescue']);require(boolean(p['acknowledge_erase']),'Acknowledge destination data loss')
        live_ack=boolean(p['acknowledge_live']);integer(p['observed_at'])
        require(0<=time.time()-p['observed_at']<=300,'Clone confirmation expired; review the disks again')
        source,target,nodes=self.context(p)
        require(pair_fingerprint(source,target,nodes)==p['fingerprint'],'Disk identity or layout changed; review the clone again')
        require(p['confirmation']=='CLONE '+target['path'],'Type the exact destination confirmation')
        live=source['path'] in system_disks(nodes)
        require(not live or live_ack,'Acknowledge that a running OS clone may be inconsistent')
        require(shutil.which('ddrescue') is not None,'GNU ddrescue is missing; install gddrescue')
        require(isinstance(self.run.job_id,str) and re.fullmatch('[a-f0-9]{32}',self.run.job_id),'A persistent clone job is required')
        folder=Path(self.config.get('clone_root','/var/lib/yanp-nas/clones'))
        folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(not folder.is_symlink() and folder.stat().st_uid==os.geteuid() and folder.stat().st_mode&0o077==0,'Clone map directory must be private and owned by the agent')
        mapfile=folder/(self.run.job_id+'.map')
        require(not mapfile.exists(),'An existing map requires local recovery; automatic resume is disabled')
        report={'state':'Preparing','source':identity(source),'destination':identity(target),'rescue':rescue,'live_source':live,
                'total_bytes':source['size'],'rescued_bytes':0,'percent':0,'remaining_bytes':source['size'],
                'mapfile':str(mapfile),'warning':'Clone duplicates filesystem and partition UUIDs. Keep it unmounted until identities are resolved. Larger GPT destinations may need backup-header relocation. Unreadable areas may retain old destination bytes.'}
        if live:report['warning']+=' The source OS is running; this is not a consistent offline backup.'
        self.publish(report)
        try:
            with contextlib.ExitStack() as stack:
                verify_source=stack.enter_context(pinned_disk(source));verify_target=stack.enter_context(pinned_disk(target))
                # A block-device O_EXCL open prevents a mounted destination from
                # being overwritten, including mount races outside this agent.
                source_fd=os.open(source['stable_id'],os.O_RDONLY|os.O_CLOEXEC|(0 if live else os.O_EXCL))
                stack.callback(os.close,source_fd)
                target_fd=os.open(target['stable_id'],os.O_RDWR|os.O_EXCL|os.O_CLOEXEC)
                stack.callback(os.close,target_fd)
                for fd,disk in ((source_fd,source),(target_fd,target)):
                    info=os.fstat(fd)
                    require(stat.S_ISBLK(info.st_mode) and f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'==disk['maj:min'],'Pinned clone device identity changed')
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                verify_source();verify_target()
                current_source,current_target,current_nodes=self.context(p)
                require(pair_fingerprint(current_source,current_target,current_nodes)==p['fingerprint'],'Disk layout changed before cloning')
                report.update(state='Cloning',started_at=int(time.time()));self.publish(report)
                # Pass pinned descriptors, never re-open a user-supplied path.
                command=clone_command('/proc/self/fd/'+str(source_fd),'/proc/self/fd/'+str(target_fd),mapfile,source['size'],source['log-sec'],rescue)
                self.run.log('GNU ddrescue '+('rescue mode, up to 3 retry passes' if rescue else 'fast mode, no trimming/scraping/retries')+'\n'+report['warning']+'\n')
                code=self.copy(command,(source_fd,target_fd),mapfile,report,verify_source,verify_target)
                os.fsync(target_fd);verify_source();verify_target()
                report['exit_code']=code
                require(code==0 and report.get('remaining_bytes')==0 and not report.get('progress_note'),'Clone incomplete: unreadable or uncopied areas remain, or ddrescue failed. Inspect the report and mapfile; no automatic retry.')
            with pinned_disk(target) as verify:
                verify()
                self.run.run(['blockdev','--rereadpt',target['stable_id']],timeout=60)
                verify()
                self.run.run(['udevadm','trigger','--action=change',str((Path('/sys/dev/block')/target['maj:min']).resolve())],timeout=40)
                self.run.run(['udevadm','settle','--timeout=30'],timeout=40)
                verify()
            report.update(state='Completed',ended_at=int(time.time()));self.publish(report)
            self.run.log('Clone completed. '+json.dumps(report)+'\n')
            return report
        except Exception as exc:
            report.update(state='Failed',error=str(exc),ended_at=int(time.time()));self.publish(report)
            self.run.log('Clone failed. '+json.dumps(report)+'\n')
            raise Error('Disk clone failed; destination may be partially overwritten. '+str(exc)) from exc

    def copy(self,command,fds,mapfile,report,*verifiers):
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                 pass_fds=fds,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while True:
                    for key,_ in selector.select(timeout=2):
                        output=os.read(key.fd,16384)
                        if output:
                            text=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',output.decode(errors='replace'))
                            self.run.log(text)
                            report['output_tail']=(report.get('output_tail','')+text)[-8192:]
                        else:selector.unregister(key.fileobj)
                    for verify in verifiers:verify()
                    try:
                        require(mapfile.stat().st_size<=32*1024**2,'Rescue map is too large for live progress')
                        report.update(map_progress(mapfile.read_text(),report['total_bytes']))
                        report.pop('progress_note',None)
                    except (OSError,ValueError,Error) as exc:
                        report['progress_note']='Waiting for a complete rescue map: '+str(exc)
                    report['updated_at']=int(time.time());self.publish(report)
                    if process.poll() is not None and not selector.get_map():break
            return process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
            process.stdout.close()

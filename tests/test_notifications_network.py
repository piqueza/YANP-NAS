# SPDX-License-Identifier: GPL-2.0-only
from decimal import Decimal
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from agent.core import Error
from agent.notifications import Notifications, validate_ack_all
from agent.system import interface_link_rates


class NotificationTests(unittest.TestCase):
    def test_ack_scopes_are_allowlisted_and_boundary_is_bound(self):
        db = Mock()
        for scope in ('all', 'attention', 'security'):
            result = Notifications(db).acknowledge_all({'scope': scope, 'through_id': 124})
            sql, params = db.execute.call_args.args
            self.assertEqual(params, (124,))
            self.assertIn('acknowledged=0 AND id<=%s', sql)
            self.assertEqual(result['scope'], scope)
            self.assertNotIn('DELETE', sql)
        self.assertIn('LOWER(kind)', sql)

    def test_rejects_unknown_scopes_and_unexpected_parameters(self):
        for params in ({}, {'scope': 'arbitrary', 'through_id': 1},
                       {'scope': 'all', 'through_id': 1, 'password': 'test-only'},
                       *({'scope': 'all', 'through_id': value} for value in (True, 0, -1, '3', None))):
            with self.subTest(params=params), self.assertRaises(Error):
                validate_ack_all(params)

    def test_summary_includes_older_events_and_serializes_decimal_counts(self):
        db = Mock()
        db.query.return_value = [{'pending_all': Decimal(150), 'pending_attention': Decimal(110), 'pending_security': Decimal(2)}]
        self.assertEqual(Notifications(db).summary(200), {'through_id': 200, 'all': 150, 'attention': 110, 'security': 2})
        sql, params = db.query.call_args.args
        self.assertEqual(params, (200,))
        self.assertNotIn('LIMIT', sql)

    def test_agent_validates_before_audit(self):
        from agent.main import Agent
        agent = Agent.__new__(Agent)
        agent.authorize = Mock(return_value={'role': 'admin'})
        agent.db = Mock()
        with self.assertRaises(Error):
            agent.request('event.ack_all', 1, {'scope': 'all', 'through_id': 1, 'password': 'test-only'})
        agent.db.audit.assert_not_called()
        agent.request('event.ack_all', 1, {'scope': 'all', 'through_id': 1})
        agent.db.audit.assert_called_once_with(1, 'event.ack_all', {'scope': 'all', 'through_id': 1})


class LinkRateTests(unittest.TestCase):
    def observe(self, speed='1000', carrier='1', **changes):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'eth-test').mkdir()
            if speed is not None:
                (root/'eth-test'/'speed').write_text(speed)
            if carrier is not None:
                (root/'eth-test'/'carrier').write_text(carrier)
            original = {'ifname': 'eth-test', 'flags': ['UP'], 'operstate': 'UP', **changes}
            result = interface_link_rates([original], root)[0]
            self.assertNotIn('link_speed_mbps', original)
            return result

    def test_negotiated_speeds_and_unknown_operstate_with_carrier(self):
        for speed in ('100', '1000', '2500', '10000'):
            self.assertEqual(self.observe(speed)['link_speed_mbps'], int(speed))
        self.assertEqual(self.observe(operstate='UNKNOWN')['link_speed_mbps'], 1000)

    def test_inactive_and_loopback_never_show_stale_speed(self):
        for changes in ({'carrier': '0'}, {'operstate': 'DOWN'}, {'flags': []}, {'ifname': 'lo'}, {'link_type': 'loopback'}):
            with self.subTest(changes=changes):
                result = self.observe(**changes)
                self.assertFalse(result['link_active'])
                self.assertIsNone(result['link_speed_mbps'])

    def test_unsupported_invalid_and_disappearing_driver_values(self):
        for speed in (None, '-1', '0', '4294967295', 'unknown'):
            with self.subTest(speed=speed):
                result = self.observe(speed)
                self.assertTrue(result['link_active'])
                self.assertIsNone(result['link_speed_mbps'])
        result = self.observe(carrier=None)
        self.assertTrue(result['link_active'])
        self.assertIsNone(result['link_speed_mbps'])

    def test_invalid_interface_names_cannot_escape_sysfs_root(self):
        for name in ('..', '../outside', '/etc', '\x00', ''):
            self.assertFalse(self.observe(ifname=name)['link_active'])


@unittest.skipUnless(shutil.which('node'), 'Node required for frontend checks')
class NotificationNetworkUITests(unittest.TestCase):
    def js(self, code):
        harness = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const app=fs.readFileSync('web/public/assets/app.js','utf8');
const context=vm.createContext({Intl,Date,setTimeout,console,document:{createElement:()=>({})},location:{hash:'#activity'}});
vm.runInContext(app.split("document.addEventListener('click'")[0],context);
const run=code=>vm.runInContext(code,context);
'''
        result = subprocess.run(['node', '-e', harness+code], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_buttons_use_global_pending_counts_and_scopes(self):
        self.js(r'''
run(`user={role:'admin',display_name:'Administrator'};state={events:[],jobs:[],audit:[],notification_summary:{through_id:250,all:140,attention:12,security:3}}`);
assert.match(run('activityPage()'),/data-action="ack-all" data-scope="all"/);
assert.match(run("acknowledgeAllButton('attention')"),/data-scope="attention"/);
assert.match(run("acknowledgeAllButton('security')"),/data-scope="security"/);
assert.equal(run("notificationCount('all')"),140);
run('state.notification_summary.all=0');assert.match(run("acknowledgeAllButton('all')"),/disabled/);
run('state.notification_summary.through_id=0');assert.equal(run("acknowledgeAllButton('all')"),'');
''')

    def test_bulk_ack_uses_displayed_boundary_and_recovers_on_failure(self):
        self.js(r'''
run(`state={notification_summary:{through_id:12,all:2}};let sent,refreshed=false;toast=()=>{};
api=async(route,p)=>{sent={route,p};state.notification_summary.through_id=13;};refresh=async()=>{refreshed=true;};`);
context.button={dataset:{action:'ack-all',scope:'all'},disabled:false,isConnected:true};
(async()=>{
 await run('clickAction(button)');
 assert.equal(run('sent.p.operation'),'event.ack_all');assert.equal(run('sent.p.params.through_id'),12);
 assert.equal(run('sent.p.params.scope'),'all');assert.equal(run('refreshed'),true);
 run("api=async()=>{throw Error('unavailable');}");
 await assert.rejects(run('clickAction(button)'),/unavailable/);assert.equal(context.button.disabled,false);
})().catch(e=>{console.error(e);process.exitCode=1;});
''')

    def test_link_rate_labels_and_html_escaping(self):
        self.js(r'''
for(const [speed,label] of [[100,'100 Mbps'],[1000,'1 Gbps'],[2500,'2.5 Gbps'],[10000,'10 Gbps']]) {
 context.nic={ifname:'eth-test',link_active:true,link_speed_mbps:speed};assert.equal(run('linkSpeedLabel(nic)'),label);
}
context.nic={ifname:'eth-test',link_active:true,link_speed_mbps:null};assert.equal(run('linkSpeedLabel(nic)'),'Link speed unavailable');
context.nic.link_active=false;assert.equal(run('linkSpeedLabel(nic)'),'');
context.nic={ifname:'lo',link_active:true,link_speed_mbps:1000};assert.equal(run('linkSpeedLabel(nic)'),'');
run(`state={system:{load:[0,0,0],memory:{total:100,available:50},interfaces:[{ifname:'<test>',operstate:'UP',link_active:true,link_speed_mbps:1000,addr_info:[]}],services:{}},updates:null,jobs:[]}`);
const html=run('systemPage()');assert.match(html,/&lt;test&gt;/);assert.match(html,/1 Gbps/);assert.ok(!html.includes('<test>'));
''')

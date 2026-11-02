# SPDX-License-Identifier: GPL-2.0-only
import unittest
from unittest.mock import MagicMock

from agent.core import Error
from agent.storage import Storage


class UserAccessTests(unittest.TestCase):
    def storage(self):
        storage=Storage({},MagicMock(),MagicMock())
        target={'id':3,'username':'yanp_new','enabled':True,'system_synced':True}
        other={'id':2,'username':'yanp_other','enabled':False,'system_synced':True,'mode':'rw'}
        def query(sql,args):
            return [other,{**target,'mode':'ro'}] if 'JOIN users' in sql else [target]
        storage.db.query.side_effect=query
        storage.directory=MagicMock()
        storage.apply_access=MagicMock()
        return storage,target,other

    def test_user_editor_preserves_other_users_live_grants_even_when_disabled(self):
        storage,target,other=self.storage()
        result=storage.user_access({'id':3,'changes':[{'directory_id':7,'mode':'rw'}]})
        storage.apply_access.assert_called_once_with(7,[(other,'rw'),(target,'rw')])
        self.assertEqual(result['directories'],[7])

    def test_removing_one_user_never_removes_other_users(self):
        storage,target,other=self.storage()
        target['enabled']=False;target['system_synced']=False
        storage.user_access({'id':3,'changes':[{'directory_id':7,'mode':'none'}]})
        storage.apply_access.assert_called_once_with(7,[(other,'rw')])

    def test_grants_require_a_ready_samba_account(self):
        storage,target,_=self.storage();target['system_synced']=False
        with self.assertRaisesRegex(Error,'synchronize'):
            storage.user_access({'id':3,'changes':[{'directory_id':7,'mode':'rw'}]})
        storage.apply_access.assert_not_called()

    def test_all_directories_are_checked_before_any_permission_is_changed(self):
        storage,_,_=self.storage()
        storage.directory.side_effect=[None,Error('Volume is read-only')]
        with self.assertRaisesRegex(Error,'read-only'):
            storage.user_access({'id':3,'changes':[{'directory_id':7,'mode':'ro'},{'directory_id':8,'mode':'rw'}]})
        storage.apply_access.assert_not_called()

    def test_duplicate_or_invalid_changes_are_rejected_before_any_acl_write(self):
        for changes in ([{'directory_id':7,'mode':'rw'}]*2,[{'directory_id':7,'mode':'owner'}]):
            storage,_,_=self.storage()
            with self.assertRaises(Error):storage.user_access({'id':3,'changes':changes})
            storage.apply_access.assert_not_called()

    def test_partial_failure_reports_what_completed(self):
        storage,_,_=self.storage()
        storage.apply_access.side_effect=[None,Error('Samba reload failed')]
        with self.assertRaisesRegex(Error,r'Completed directory IDs: \[7\].*partly changed'):
            storage.user_access({'id':3,'changes':[{'directory_id':7,'mode':'ro'},{'directory_id':8,'mode':'rw'}]})

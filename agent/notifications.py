# SPDX-License-Identifier: GPL-2.0-only
"""Acknowledge stored events without consuming newly arriving notifications."""
from .core import integer, keys, require

SCOPES = {
    'all':'1=1',
    'attention':"severity IN ('warning','error')",
    'security':"LOWER(kind) REGEXP 'security|firewall|fail2ban'",
}


def validate_ack_all(params):
    keys(params,('scope','through_id'))
    require(isinstance(params['scope'],str) and params['scope'] in SCOPES,'Unknown notification scope')
    integer(params['through_id'])


class Notifications:
    def __init__(self, db):
        self.db = db

    def summary(self, through_id):
        fields = ','.join(f'COALESCE(SUM(acknowledged=0 AND ({predicate})),0) AS pending_{scope}'
                          for scope,predicate in SCOPES.items())
        row = self.db.query('SELECT '+fields+' FROM events WHERE id<=%s',(through_id,))[0]
        return {'through_id':through_id,**{scope:int(row['pending_'+scope]) for scope in SCOPES}}

    def acknowledge_all(self, params):
        validate_ack_all(params)
        # The predicate comes only from this allowlist; the boundary is a bound
        # integer. It includes older rows outside the UI's 100-event page.
        self.db.execute('UPDATE events SET acknowledged=1 WHERE acknowledged=0 AND id<=%s AND ('
                        +SCOPES[params['scope']]+')',(params['through_id'],))
        return {'state':'Acknowledged','scope':params['scope'],'through_id':params['through_id']}

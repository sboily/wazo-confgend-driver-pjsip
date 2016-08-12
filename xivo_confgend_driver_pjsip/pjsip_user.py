# -*- coding: UTF-8 -*-

# Copyright (C) 2016 Sylvain Boily
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from __future__ import unicode_literals

def from_nat(val):
    if 'yes' in val:
        yield 'rtp_symmetric = yes'
        yield 'rewrite_contact = yes'
    if 'comedia' in val:
        yield 'rtp_symmetric = yes'
    if 'force_port' in val:
        yield 'force_rport = yes'
        yield 'rewrite_contact = yes'

def from_sendrpid(val):
    if val == 'yes' or val == 'rpid':
        yield 'send_rpid = yes'
    elif val == 'pai':
        yield 'send_pai = yes'

def set_media_encryption(val):
    if val == 'yes':
        yield 'media_encryption = sdes'

def from_progressinband(val):
    yield ''

def from_mailbox(val):
    yield ''

def from_dtlsenable(val):
    yield 'media_encryption = dtls'

def set_dtmf_mode(val):
    if val == 'rfc2833':
        yield 'dtmf_mode = rfc4733'
    else:
        yield 'dtmf_mode = {}'.format(val)

def set_timers(val):
    if val == 'originate':
        yield 'timers = always'
    elif val == 'accept':
        yield 'timers = required'
    elif val == 'never':
        yield 'timers = no'
    else:
        yield 'timers = yes'

def set_direct_media(val):
    if 'yes' in val:
        yield 'direct_media = yes'
    if 'update' in val:
        yield 'direct_media_method = update'
    if 'outgoing' in val:
        yield 'directed_media_glare_mitigation = outgoing'
    if 'nonat' in val:
        yield 'disable_directed_media_on_nat = yes'
    if 'no' in val:
        yield 'direct_media = no'

class PJSipUserGenerator(object):

    EXCLUDE_OPTIONS = ('name',
                       'protocol',
                       'category',
                       'initialized',
                       'disallow',
                       'regseconds',
                       'lastms',
                       'name',
                       'fullcontact',
                       'ipaddr')


    SIP_TO_PJSIP = {
        'dtmfmode': set_dtmf_mode,
        'nat': from_nat,
        'icesupport': 'ice_support',
        'autoframing': 'use_ptime',
        'outboundproxy': 'outbound_proxy',
        'mohsuggest': 'moh_suggest',
        'session-timers': set_timers,
        'session-minse': 'timers_min_se',
        'session-expires': 'timers_sess_expires',
        'externip': 'external_media_address',
        'externhost': 'external_media_address',
        'directmedia': set_direct_media,
        'callingpres': 'callerid_privacy',
        'cid_tag': 'callerid_tag',
        'trustpid': 'trust_id_inbound',
        'sendrpid': from_sendrpid,
        'encrpytion': set_media_encryption,
        'avpf': 'use_avpf',
        'progressinband': from_progressinband,
        'callgroup': 'call_group',
        'pickupgroup': 'pickup_group',
        'namedcallgroup': 'named_call_group',
        'namedpickupgroup': 'named_pickup_group',
        'allowtransfer': 'allow_transfer',
        'fromuser': 'from_user',
        'fromdomain': 'from_domain',
        'mwifrom': 'mwi_from_user',
        'sdpowner': 'sdp_owner',
        'sdpsession': 'sdp_session',
        'tonezone': 'tone_zone',
        'allowsubscribe': 'allow_subscribe',
        'subminexpiry': 'sub_min_expiry',
        'mailbox': from_mailbox,
        'busylevel': 'device_state_busy_at',
        'dtlsenable': from_dtlsenable,
        'dtlsverify': 'dtls_verify',
        'dtlsrekey': 'dtls_rekey',
        'dtlscertfile': 'dtls_cert_file',
        'dtlsprivatekey': 'dtls_private_key',
        'dtlscipher': 'dtls_cipher',
        'dtlscafile': 'dtls_ca_file',
        'dtlscapath': 'dtls_ca_path',
        'dtlssetup': 'dtls_setup',
        'setvar': 'set_var',
    }

    def __init__(self, dao):
        self.dao = dao

    def generate(self):
        for row in self.dao.find_sip_user_settings():
            for line in self.format_row(row):
                yield line

    def format_row(self, row):
        username = row.UserSIP.name
        options = row.UserSIP.all_options(self.EXCLUDE_OPTIONS)

        yield '[{}]'.format(username)
        for line in self.format_aor_options():
            yield line
        yield ''

        yield '[{}]'.format(username)
        for line in self.format_auth_options(username, options):
            yield line
        yield ''

        yield '[{}]'.format(username)
        for line in self.format_endpoint_options(username, options):
            yield line
        for line in self.format_user_options(row):
            yield line
        yield ''

    def format_aor_options(self):
        yield 'type = aor'
        yield 'max_contacts = 1'

    def format_auth_options(self, username, options):
        yield 'type = auth'
        yield 'auth_type = userpass'
        yield 'username = {}'.format(username)
        for name, value in options:
            if name == 'secret':
                yield 'password = {}'.format(value)

    def format_endpoint_options(self, username, options):
        yield 'type = endpoint'
        yield 'transport = simpletrans'
        for name, value in options:
            if name == 'allow':
                yield 'disallow = all'
                yield 'allow = {}'.format(value)
            if self.SIP_TO_PJSIP.has_key(name):
                if hasattr(self.SIP_TO_PJSIP[name], '__call__'):
                    for line in self.SIP_TO_PJSIP[name](value):
                        yield line
                else:
                    yield '{} = {}'.format(self.SIP_TO_PJSIP[name], value)
        yield 'auth = {}'.format(username)
        yield 'aors = {}'.format(username)

    def format_user_options(self, row):
        if row.context:
            yield 'set_var = TRANSFER_CONTEXT={}'.format(row.context)
        if row.number and row.context:
            yield 'set_var = PICKUPMARK={}%{}'.format(row.number, row.context)
        if row.uuid:
            yield 'set_var = XIVO_USERUUID={}'.format(row.uuid)
        if row.user_id:
            yield 'set_var = XIVO_USERID={}'.format(row.user_id)
        if row.namedpickupgroup:
            yield 'named_pickup_group = {}'.format(row.namedpickupgroup)
        if row.namedpickupgroup:
            yield 'named_call_group = {}'.format(row.namedcallgroup)
        if row.mohsuggest:
            yield 'moh_suggest = {}'.format(row.mohsuggest)
        if row.mailbox:
            yield 'mailboxes = {}'.format(row.mailbox)


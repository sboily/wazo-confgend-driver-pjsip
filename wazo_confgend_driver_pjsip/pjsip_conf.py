# -*- coding: utf-8 -*-
# Copyright 2018 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0+
from __future__ import unicode_literals

from collections import namedtuple
from xivo_dao import asterisk_conf_dao

Section = namedtuple('Section', ['name', 'type_', 'templates', 'fields'])


class Registration(object):
    """
    Class for parsing and storing information in a register line in sip.conf.
    """
    def __init__(self, line):
        self.parse(line)

        self.section = 'reg_' + self.host
        self.registration_fields = []

        self.auth_section = 'auth_reg_' + self.host
        self.auth_fields = []

        self._generate()

    def parse(self, line):
        """
        Initial parsing routine for register lines in sip.conf.

        This splits the line into the part before the host, and the part
        after the '@' symbol. These two parts are then passed to their
        own parsing routines
        """

        # register =>
        # [peer?][transport://]user[@domain][:secret[:authuser]]@host[:port][/extension][~expiry]

        prehost, at, host_part = line.rpartition('@')
        if not prehost:
            raise

        self.parse_host_part(host_part)
        self.parse_user_part(prehost)

    def parse_host_part(self, host_part):
        """
        Parsing routine for the part after the final '@' in a register line.
        The strategy is to use partition calls to peel away the data starting
        from the right and working to the left.
        """
        pre_expiry, sep, expiry = host_part.partition('~')
        pre_extension, sep, self.extension = pre_expiry.partition('/')
        self.host, sep, self.port = pre_extension.partition(':')

        self.expiry = expiry if expiry else '120'

    def parse_user_part(self, user_part):
        """
        Parsing routine for the part before the final '@' in a register line.
        The only mandatory part of this line is the user portion. The strategy
        here is to start by using partition calls to remove everything to
        the right of the user, then finish by using rpartition calls to remove
        everything to the left of the user.
        """
        self.peer = ''
        self.protocol = 'udp'
        protocols = ['udp', 'tcp', 'tls']
        for protocol in protocols:
            position = user_part.find(protocol + '://')
            if -1 < position:
                post_transport = user_part[position + 6:]
                self.peer, sep, self.protocol = user_part[:position + 3].rpartition('?')
                user_part = post_transport
                break

        colons = user_part.count(':')
        if (colons == 3):
            # :domainport:secret:authuser
            pre_auth, sep, port_auth = user_part.partition(':')
            self.domainport, sep, auth = port_auth.partition(':')
            self.secret, sep, self.authuser = auth.partition(':')
        elif (colons == 2):
            # :secret:authuser
            pre_auth, sep, auth = user_part.partition(':')
            self.secret, sep, self.authuser = auth.partition(':')
        elif (colons == 1):
            # :secret
            pre_auth, sep, self.secret = user_part.partition(':')
        elif (colons == 0):
            # No port, secret, or authuser
            pre_auth = user_part
        else:
            # Invalid setting
            raise

        self.user, sep, self.domain = pre_auth.partition('@')

    def _generate(self):
        """
        Write parsed registration data into a section in pjsip.conf

        Most of the data in self will get written to a registration section.
        However, there will also need to be an auth section created if a
        secret or authuser is present.

        General mapping of values:
        A combination of self.host and self.port is server_uri
        A combination of self.user, self.domain, and self.domainport is
          client_uri
        self.expiry is expiration
        self.extension is contact_user
        self.protocol will map to one of the mapped transports
        self.secret and self.authuser will result in a new auth section, and
          outbound_auth will point to that section.
        XXX self.peer really doesn't map to anything :(
        """

        if self.extension:
            self.registration_fields.append(('contact_user', self.extension))

        self.registration_fields.append(('expiration', self.expiry))
        self.registration_fields.append(('transport', 'transport-{}'.format(self.protocol)))

        if hasattr(self, 'secret') and self.secret:
            self.auth_fields.append(('password', self.secret))
            self.auth_fields.append(('username', getattr(self, 'authuser', None) or self.user))
            self.registration_fields.append(('outbound_auth', self.auth_section))

        client_uri = "sip:%s@" % self.user
        if self.domain:
            client_uri += self.domain
        else:
            client_uri += self.host

        if hasattr(self, 'domainport') and self.domainport:
            client_uri += ":" + self.domainport
        elif self.port:
            client_uri += ":" + self.port
        self.registration_fields.append(('client_uri', client_uri))

        server_uri = "sip:%s" % self.host
        if self.port:
            server_uri += ":" + self.port
        self.registration_fields.append(('server_uri', server_uri))


class AsteriskConfFileGenerator(object):

    def generate(self, sections):
        lines = []

        for section in sections:
            if not section:
                continue
            name, type_, templates, fields = section
            fields = fields or []
            header = self._build_header(name, type_, templates)

            lines.append(header)
            for key, value in fields:
                lines.append('{} = {}'.format(key, value))
            lines.append('')

        return '\n'.join(lines)

    def _build_header(self, name, type_, templates):
        templates = templates or []
        in_parens = []

        if type_ == 'extends':
            in_parens.append('+')
        elif type_ == 'template':
            in_parens.append('!')

        for template in templates:
            in_parens.append(template)

        end = '({})'.format(','.join(in_parens)) if in_parens else ''
        return '[{}]{}'.format(name, end)


class SipDBExtractor(object):

    sip_general_to_global = [
        ('useragent', 'user_agent'),
        ('sipdebug', 'debug'),
        ('legacy_useroption_parsing', 'ignore_uri_user_options'),
    ]
    sip_general_to_system = [
        ('timert1', 'timer_t1'),
        ('timerb', 'timer_b'),
        ('compactheaders', 'compact_headers'),
    ]
    sip_general_to_transport = [
        ('media_address', 'external_media_address'),
    ]
    sip_general_to_register_tpl = [
        ('registertimeout', 'retry_interval'),
        ('registerattempts', 'max_retries'),
    ]
    sip_to_aor = [
        ('qualifyfreq', 'qualify_frequency'),
        ('maxexpiry', 'maximum_expiration'),
        ('minexpiry', 'minimum_expiration'),
        ('defaultexpiry', 'default_expiration'),
    ]
    sip_to_endpoint = [
        ('allowsubscribe', 'allow_subscribe'),
        ('allowtransfer', 'allow_transfer'),
        ('autoframing', 'use_ptime'),
        ('avpf', 'use_avpf'),
        ('callerid', 'callerid'),
        ('callingpres', 'callerid_privacy'),
        ('cid_tag', 'callerid_tag'),
        ('cos_audio', 'cos_audio'),
        ('cos_video', 'cos_video'),
        ('fromdomain', 'from_domain'),
        ('fromdomain', 'from_domain'),
        ('fromuser', 'from_user'),
        ('icesupport', 'ice_support'),
        ('language', 'language'),
        ('mohsuggest', 'moh_suggest'),
        ('mwifrom', 'mwi_from_user'),
        ('outboundproxy', 'outbound_proxy'),
        ('rtp_engine', 'rtp_engine'),
        ('rtptimeout', 'rtp_timeout'),
        ('sdpowner', 'sdp_owner'),
        ('sdpowner', 'sdp_owner'),
        ('sdpsession', 'sdp_session'),
        ('sdpsession', 'sdp_session'),
        ('send_diversion', 'send_diversion'),
        ('session-expires', 'timers_sess_expires'),
        ('session-minse', 'timers_min_se'),
        ('subminexpiry', 'sub_min_expiry'),
        ('tonezone', 'tone_zone'),
        ('tos_audio', 'tos_audio'),
        ('tos_video', 'tos_video'),
        ('trustpid', 'trust_id_inbound'),
        ('busylevel', 'device_state_busy_at'),
        ('dtlsverify', 'dtls_verify'),
        ('dtlsrekey', 'dtls_rekey'),
        ('dtlscertfile', 'dtls_cert_file'),
        ('dtlsprivatekey', 'dtls_private_key'),
        ('dtlscipher', 'dtls_cipher'),
        ('dtlscafile', 'dtls_ca_file'),
        ('dtlscapath', 'dtls_ca_path'),
        ('dtlssetup', 'dtls_setup'),
        ('webrtc', 'webrtc'),
    ]

    def __init__(self):
        self._static_sip = asterisk_conf_dao.find_sip_general_settings()
        self._auth_data = asterisk_conf_dao.find_sip_authentication_settings()
        self._user_sip = list(asterisk_conf_dao.find_sip_user_settings())
        self._trunk = asterisk_conf_dao.find_sip_trunk_settings()
        self._general_settings_dict = {}

        for row in self._static_sip:
            self._general_settings_dict[row['var_name']] = row['var_val']

    def get(self, section):
        if section == 'global':
            return self._get_global()
        elif section == 'system':
            return self._get_system()
        elif section == 'transport-udp':
            return self._get_transport_udp()
        elif section == 'transport-wss':
            return self._get_transport_wss()
        elif section == 'wazo-general-aor':
            return self._get_general_aor_template()
        elif section == 'wazo-general-endpoint':
            return self._get_general_endpoint_template()
        elif section == 'wazo-general-registration':
            return self._get_general_registration_template()

    def get_trunk_sections(self):
        for registration_section in self._get_registration_sections(self._static_sip):
            yield registration_section

        for trunk_sip, twillio_incoming in self._trunk:
            for section in self._get_trunk(trunk_sip, twillio_incoming):
                yield section

    def get_user_sections(self):
        for user_sip, pickup_groups in self._user_sip:
            for section in self._get_user(user_sip, pickup_groups):
                yield section

    def _get_user(self, user_sip, pickup_groups):
        yield self._get_user_endpoint(user_sip, pickup_groups)
        yield self._get_user_aor(user_sip)
        yield self._get_user_auth(user_sip)

    def _get_trunk(self, trunk_sip, twillio_incoming):
        yield self._get_trunk_aor(trunk_sip)
        yield self._get_trunk_identify(trunk_sip)
        yield self._get_trunk_auth(trunk_sip)
        yield self._get_trunk_endpoint(trunk_sip, twillio_incoming)

    def _get_registration_sections(self, sip_general):
        for row in sip_general:
            if row['var_name'] != 'register':
                continue
            register = Registration(row['var_val'])

            fields = register.registration_fields
            fields.append(('type', 'registration'))
            fields.append(('outbound_auth', register.auth_section))
            yield Section(
                name=register.section,
                type_='section',
                templates=['wazo-general-registration'],
                fields=fields,
            )

            fields = register.auth_fields
            fields.append(('type', 'auth'))
            yield Section(
                name=register.auth_section,
                type_='section',
                templates=None,
                fields=fields,
            )

    def _get_trunk_aor(self, trunk_sip):
        fields = [
            ('type', 'aor'),
        ]

        self._add_from_mapping(fields, self.sip_to_aor, trunk_sip.__dict__)

        host = trunk_sip.host
        if host == 'dynamic':
            self._add_option(fields, ('max_contacts', 1))

        result = 'sip:'
        # More difficult case. The host will be either a hostname or
        # IP address and may or may not have a port specified. pjsip.conf
        # expects the contact to be a SIP URI.

        user = trunk_sip.username
        if user:
            result += user + '@'

        host_port = '{}:{}'.format(trunk_sip.host, trunk_sip.port)
        result += host_port

        self._add_option(fields, ('contact', result))

        return Section(
            name=trunk_sip.name,
            type_='section',
            templates=['wazo-general-aor'],
            fields=fields,
        )

    def _get_trunk_identify(self, trunk_sip):
        fields = [
            ('type', 'identify'),
            ('endpoint', trunk_sip.name),
            ('match', trunk_sip.host),
        ]

        return Section(
            name=trunk_sip.name,
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_user_aor(self, user_sip):
        fields = [
            ('type', 'aor'),
        ]

        self._add_from_mapping(fields, self.sip_to_aor, user_sip[0].__dict__)

        host = user_sip[0].host
        if host == 'dynamic':
            self._add_option(fields, ('max_contacts', 1))

        if user_sip.mailbox and user_sip[0].subscribemwi == 'yes':
            self._add_option(fields, ('mailboxes', user_sip.mailbox))

        return Section(
            name=user_sip[0].name,
            type_='section',
            templates=['wazo-general-aor'],
            fields=fields,
        )

    def _get_user_auth(self, user_sip):
        fields = [
            ('type', 'auth'),
            ('username', user_sip[0].name),
            ('password', user_sip[0].secret),
        ]

        return Section(
            name=user_sip[0].name,
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_trunk_auth(self, trunk_sip):
        fields = [
            ('type', 'auth'),
            ('username', trunk_sip.name),
            ('password', trunk_sip.secret),
        ]

        return Section(
            name=trunk_sip.name,
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_user_endpoint(self, user_sip, pickup_groups):
        user_dict = user_sip[0].__dict__
        all_options = user_sip[0].all_options()

        for key, value in all_options:
            user_dict[key] = value

        fields = [
            ('type', 'endpoint'),
            ('context', user_dict['context']),
            ('aors', user_sip[0].name),
            ('set_var', 'XIVO_ORIGINAL_CALLER_ID={callerid}'.format(**user_dict)),
            ('set_var', 'TRANSFER_CONTEXT={}'.format(user_sip.context)),
            ('set_var', 'PICKUPMARK={}%{}'.format(user_sip.number, user_sip.context)),
            ('set_var', 'XIVO_USERID={}'.format(user_sip.user_id)),
            ('set_var', 'XIVO_USERUUID={}'.format(user_sip.uuid)),
            ('set_var', 'WAZO_CHANNEL_DIRECTION=from-wazo'),
        ]

        for key, value in all_options:
            if key in ('allow', 'disallow'):
                self._add_option(fields, (key, value))

        named_pickup_groups = ','.join(str(id) for id in pickup_groups.get('pickupgroup', []))
        if named_pickup_groups:
            self._add_option(fields, ('named_pickup_group', named_pickup_groups))

        named_call_groups = ','.join(str(id) for id in pickup_groups.get('callgroup', []))
        if named_call_groups:
            self._add_option(fields, ('named_call_group', named_call_groups))

        self._add_from_mapping(fields, self.sip_to_endpoint, user_dict)
        self._add_option(fields, self._convert_dtmfmode(user_dict))
        self._add_option(fields, self._convert_session_timers(user_dict))
        self._add_option(fields, self._convert_sendrpid(user_dict))
        self._add_option(fields, self._convert_encryption(user_dict))
        self._add_option(fields, self._convert_progressinband(user_dict))
        self._add_option(fields, self._convert_dtlsenable(user_dict))
        self._add_option(fields, self._convert_encryption_taglen(self._general_settings_dict))
        for pair in self._convert_nat(user_dict):
            self._add_option(fields, pair)
        for pair in self._convert_directmedia(user_dict):
            self._add_option(fields, pair)
        for pair in self._convert_recordonfeature(user_dict):
            self._add_option(fields, pair)
        for pair in self._convert_recordofffeature(user_dict):
            self._add_option(fields, pair)

        if user_sip.mailbox and user_dict.get('subscribemwi') != 'yes':
            self._add_option(fields, ('mailboxes', user_sip.mailbox))

        if user_dict.get('transport') == 'wss':
            self._add_option(fields, ('transport', 'transport-wss'))

        return Section(
            name=user_sip[0].name,
            type_='section',
            templates=['wazo-general-endpoint'],
            fields=fields,
        )

    def _get_trunk_endpoint(self, trunk_sip, twillio_incoming):
        trunk_dict = trunk_sip.__dict__
        all_options = trunk_sip.all_options()

        for key, value in all_options:
            trunk_dict[key] = value

        fields = [
            ('type', 'endpoint'),
            ('context', trunk_dict['context']),
            ('aors', trunk_sip.name),
            ('auth', trunk_sip.name),
            ('outbound_auth', trunk_sip.name),
        ]

        for key, value in all_options:
            if key in ('allow', 'disallow'):
                self._add_option(fields, (key, value))

        self._add_from_mapping(fields, self.sip_to_endpoint, trunk_dict)
        self._add_option(fields, self._convert_dtmfmode(trunk_dict))
        self._add_option(fields, self._convert_session_timers(trunk_dict))
        self._add_option(fields, self._convert_sendrpid(trunk_dict))
        self._add_option(fields, self._convert_encryption(trunk_dict))
        self._add_option(fields, self._convert_progressinband(trunk_dict))
        self._add_option(fields, self._convert_dtlsenable(trunk_dict))
        self._add_option(fields, self._convert_encryption_taglen(trunk_dict))
        for pair in self._convert_nat(trunk_dict):
            self._add_option(fields, pair)
        for pair in self._convert_directmedia(trunk_dict):
            self._add_option(fields, pair)

        return Section(
            name=trunk_sip.name,
            type_='section',
            templates=['wazo-general-endpoint'],
            fields=fields,
        )

    def _get_general_aor_template(self):
        fields = [
            ('type', 'aor'),
        ]

        self._add_from_mapping(fields, self.sip_to_aor, self._general_settings_dict)

        return Section(
            name='wazo-general-aor',
            type_='template',
            templates=None,
            fields=fields,
        )

    def _get_general_endpoint_template(self):
        fields = [
            ('type', 'endpoint'),
            ('allow', '!all,ulaw'),
        ]

        self._add_from_mapping(fields, self.sip_to_endpoint, self._general_settings_dict)

        self._add_option(fields, self._convert_dtmfmode(self._general_settings_dict))
        self._add_option(fields, self._convert_session_timers(self._general_settings_dict))
        self._add_option(fields, self._convert_sendrpid(self._general_settings_dict))
        self._add_option(fields, self._convert_encryption(self._general_settings_dict))
        self._add_option(fields, self._convert_progressinband(self._general_settings_dict))
        self._add_option(fields, self._convert_dtlsenable(self._general_settings_dict))
        self._add_option(fields, self._convert_encryption_taglen(self._general_settings_dict))
        for pair in self._convert_nat(self._general_settings_dict):
            self._add_option(fields, pair)
        for pair in self._convert_directmedia(self._general_settings_dict):
            self._add_option(fields, pair)
        for pair in self._convert_recordonfeature(self._general_settings_dict):
            self._add_option(fields, pair)
        for pair in self._convert_recordofffeature(self._general_settings_dict):
            self._add_option(fields, pair)

        return Section(
            name='wazo-general-endpoint',
            type_='template',
            templates=None,
            fields=fields,
        )

    def _get_general_registration_template(self):
        fields = [
            ('type', 'registration'),
            # ('transport', 'transport-udp'),
        ]

        self._add_from_mapping(fields, self.sip_general_to_register_tpl, self._general_settings_dict)
        outbound_proxy = self._general_settings_dict.get('outboundproxy')
        if outbound_proxy:
            self._add_option(fields, ('outboundproxy', outbound_proxy))

        return Section(
            name='wazo-general-registration',
            type_='template',
            templates=None,
            fields=fields,
        )

    def _get_global(self):
        fields = [
            ('type', 'global'),
        ]

        self._add_from_mapping(fields, self.sip_general_to_global, self._general_settings_dict)

        return Section(
            name='global',
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_system(self):
        fields = [
            ('type', 'system'),
        ]

        self._add_from_mapping(fields, self.sip_general_to_system, self._general_settings_dict)

        return Section(
            name='system',
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_transport(self, protocol):
        fields = [
            ('type', 'transport'),
            ('protocol', protocol),
        ]

        bind = self._general_settings_dict.get('udpbindaddr')
        port = self._general_settings_dict.get('bindport')
        if port:
            bind += ':{}'.format(port)

        fields.append(('bind', bind))

        extern_ip = self._general_settings_dict.get('externip')
        extern_host = self._general_settings_dict.get('externhost')
        extern_signaling_address = extern_host or extern_ip
        if extern_signaling_address:
            fields.append(('external_signaling_address', extern_signaling_address))

        for row in self._static_sip:
            if row['var_name'] != 'localnet':
                continue
            fields.append(('local_net', row['var_val']))

        return Section(
            name='transport-{}'.format(protocol),
            type_='section',
            templates=None,
            fields=fields,
        )

    def _get_transport_udp(self):
        return self._get_transport('udp')

    def _get_transport_wss(self):
        if not self._general_settings_dict.get('websocket_enabled'):
            return

        return self._get_transport('wss')

    def _add_from_mapping(self, fields, mapping, config):
        for sip_key, pjsip_key in mapping:
            value = config.get(sip_key)
            if not value:
                continue
            fields.append((pjsip_key, value))

    @staticmethod
    def _add_option(fields, pair):
        if not pair:
            return

        fields.append(pair)

    @staticmethod
    def _convert_directmedia(sip_config):
        val = sip_config.get('directmedia')
        if not val:
            return

        if 'yes' in val:
            yield 'direct_media', 'yes'
        if 'update' in val:
            yield 'direct_media_method', 'update'
        if 'outgoing' in val:
            yield 'direct_media_glare_mitigation', 'outgoing'
        if 'nonat' in val:
            yield 'disable_directed_media_on_nat', 'yes'
        if val == 'no':
            yield 'direct_media', 'no'

    @staticmethod
    def _convert_dtlsenable(sip_config):
        val = sip_config.get('dtlsenable')
        if val == 'yes':
            return 'media_encryption', 'dtls'

    @staticmethod
    def _convert_dtmfmode(sip_config):
        val = sip_config.get('dtmfmode')
        if not val:
            return

        key = 'dtmf_mode'
        if val == 'rfc2833':
            return key, 'rfc4733'
        else:
            return key, val

    @staticmethod
    def _convert_encryption(sip_config):
        val = sip_config.get('encryption')
        if val == 'yes':
            return 'media_encryption', 'sdes'

    @staticmethod
    def _convert_encryption_taglen(sip_config):
        val = sip_config.get('encryption_taglen')
        if val == 32:
            return 'srtp_tag_32', 'yes'

    @staticmethod
    def _convert_nat(sip_config):
        val = sip_config.get('nat')
        if val == 'yes':
            yield 'rtp_symmetric', 'yes'
            yield 'rewrite_contact', 'yes'
        elif val == 'comedia':
            yield 'rtp_symmetric', 'yes'
        elif val == 'force_rport':
            yield 'force_rport', 'yes'
            yield 'rewrite_contact', 'yes'

    @staticmethod
    def _convert_progressinband(sip_config):
        val = sip_config.get('progressinband')
        if val in ('no', 'never'):
            return 'inband_progress', 'no'
        elif val == 'yes':
            return 'inband_progress', 'yes'

    @staticmethod
    def _convert_recordonfeature(sip_config):
        val = sip_config.get('recordonfeature')
        if not val:
            return
        if val == 'automixmon':
            yield 'one_touch_recording', 'yes'
        yield 'record_on_feature', val

    @staticmethod
    def _convert_recordofffeature(sip_config):
        val = sip_config.get('recordofffeature')
        if not val:
            return
        if val == 'automixmon':
            yield 'one_touch_recording', 'yes'
        yield 'record_off_feature', val

    @staticmethod
    def _convert_sendrpid(sip_config):
        val = sip_config.get('sendrpid')
        if val in ('yes', 'rpid'):
            return 'send_rpid', 'yes'
        elif val == 'pai':
            return 'send_pai', 'yes'

    @staticmethod
    def _convert_session_timers(sip_config):
        val = sip_config.get('session-timers')
        if not val:
            return

        new_val = 'yes'
        if val == 'originate':
            new_val = 'always'
        elif val == 'accept':
            new_val = 'required'
        elif val == 'never':
            new_val = 'no'

        return 'timers', new_val


class PJSIPConfGenerator(object):

    def __init__(self, dependencies):
        self._config_file_generator = AsteriskConfFileGenerator()

    def generate(self):
        extractor = SipDBExtractor()

        global_sections = [
            extractor.get('global'),
            extractor.get('system'),
            extractor.get('transport-udp'),
            extractor.get('transport-wss'),
            extractor.get('wazo-general-aor'),
            extractor.get('wazo-general-endpoint'),
            extractor.get('wazo-general-registration'),
        ]
        user_sections = list(extractor.get_user_sections())
        trunk_sections = list(extractor.get_trunk_sections())

        return self._config_file_generator.generate(
            global_sections + user_sections + trunk_sections)

# -*- coding: utf-8 -*-

# Copyright (C) 2016 Sylvain Boily
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

from StringIO import StringIO

from xivo_dao.helpers.db_utils import session_scope
from xivo_dao import asterisk_conf_dao

from wazo_confgend_driver_pjsip.pjsip_user import PJSipUserGenerator


class PJSipConfGenerator(object):

    def __init__(self, config):
        self._config = config

    def generate(self):
        user_generator = PJSipUserGenerator(asterisk_conf_dao)
        config_generator = PJSipConf(user_generator)
        output = StringIO()
        config_generator.generate(output)
        return output.getvalue()

class PJSipConf(object):

    def __init__(self, user_generator):
        self.user_generator = user_generator

    def generate(self, output):
        with session_scope():
            self._generate(output)

    def _generate(self, output):
        self._gen_general(output)
        print >> output

        self._gen_user(output)
        print >> output

    def _gen_general(self, output):
        print >> output, '[simpletrans]'
        print >> output, 'type=transport'
        print >> output, 'protocol=udp'
        print >> output, 'bind=0.0.0.0:5070\n'

        print >> output, '[transport-wss]'
        print >> output, 'type=transport'
        print >> output, 'protocol=wss'
        print >> output, 'bind=0.0.0.0:5070'
        print >> output, 'local_net=192.168.0.0/16'
        print >> output, 'local_net=172.16.0.0/16'
        print >> output, 'external_media_address=172.16.42.58'
        print >> output, 'external_signaling_address=172.16.42.58'

    def _gen_user(self, output):
        for line in self.user_generator.generate():
            print >> output, line

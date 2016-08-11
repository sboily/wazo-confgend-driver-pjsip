#
# Makefile for XiVO confgend pjsip driver
# Copyright (C) 2016, Sylvain Boily
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 3. See the LICENSE file
# at the top of the source tree.
#

install:
	python setup.py install
	cp etc/asterisk/pjsip.conf /etc/asterisk/
	cp etc/xivo-confgend/conf.d/* /etc/xivo-confgend/conf.d/
	chown asterisk.www-data /etc/asterisk/pjsip.conf
	chmod 660 /etc/asterisk/pjsip.conf
	sed -i '/\(^noload.*pjsip.*\)/s/^/;/' /etc/asterisk/modules.conf
	systemctl restart xivo-confgend
	systemctl restart asterisk

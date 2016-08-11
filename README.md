Confgend driver for PJSIP
=========================

Clone the repo and install it.

    python setup.py install

Copy the configuration in asterisk and xivo-confgend config directory.

Comment with ";" all pjsip noload modules in /etc/asterisk/modules.conf.

Restart your asterisk

    systemctl restart asterisk

By default PJSIP channel listen on 5070 udp port.

Confgend driver for PJSIP
=========================

This plugin add a pjsip driver to xivo-confgend. It use the sip configuration from chan_sip store by xivo and convert it to chan_pjsip on live.

WARNING: Use xivo >= 16.10, works only with users, trunk is not supported.

Clone the repo and install it.

    make install

By default PJSIP channel listen on 5070 udp port.

Please add on your user the pjsip subroutine.

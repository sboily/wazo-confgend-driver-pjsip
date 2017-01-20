Confgend driver for PJSIP
=========================

This plugin add a pjsip driver to xivo-confgend. It use the sip configuration from chan_sip store by wazo and convert it to chan_pjsip on live.

WARNING: Use wazo >= 17.01, works only with users, trunk is not supported.

Clone the repo and install it.

    make install

By default PJSIP channel listen on 5070 udp port.

Please add on your user the pjsip subroutine named "pjsip".

To enable webrtc with pjsip, you need to add webrtc_enabled to no in your general chan_sip configuration.

#!/bin/sh

#absolute path since su has no environ vars, force gateway ip, as I could not find another solution
/data/data/com.termux/files/usr/bin/python3 gta_online_solo_public.py --gateway_ip=192.168.0.1

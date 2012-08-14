#!/bin/bash

#
# recovery tests based on 10 sec io timeout
#


dev=$1

echo test lockspace storage loss, recovery by lease release using killpath
echo messages: sanlock check lease warn/fail, kill 100, all pids clear
echo messages: wdmd warn, close, fail
echo messages: killpath_pause
date
set -x
./clientn 4 start $dev 1 /root/killpath_pause
sleep 5
./clientn 4 error $dev
sleep 150
./clientn 4 resume $dev 1
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test lockspace storage loss, recovery by escalation from killpath to sigkill
echo messages: sanlock check lease warn/fail, kill 100, kill 9, dead, all pids clear
echo messages: wdmd warn, close, fail
echo messages: killpath_args
date
set -x
./clientn 4 start $dev 1 /root/killpath_args
sleep 5
./clientn 4 error $dev
sleep 150
./clientn 4 linear $dev 1
sleep 5
set +x


echo test lockspace storage loss, recovery by pid exit using killpath
echo messages: sanlock check lease warn/fail, kill 100, dead, all pids clear
echo messages: wdmd warn, close, fail
echo messages: killpath_term
date
set -x
./clientn 4 start $dev 1 /root/killpath_term
sleep 5
./clientn 4 error $dev
sleep 150
./clientn 4 linear $dev 1
sleep 5
set +x


echo test lockspace storage loss, recovery by pid sigterm without killpath
echo messages: sanlock check lease warn/fail, kill 15, dead, all pids clear
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 none
sleep 5
./clientn 4 error $dev
sleep 150
./clientn 4 linear $dev 1
sleep 5
set +x


echo test lockspace storage delay, small enough to have no effect
echo messages: none
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 iodelay $dev 57
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test lockspace storage delay, long enough to produce sanlock warning,
echo but not failure, not long enough for wdmd warn or close
echo messages: sanlock check lease warn
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 iodelay $dev 67
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test lockspace storage delay, long enough to produce sanlock warning,
echo but not failure/recovery, long enough for wdmd warn and close
echo messages: sanlock check lease warn
echo messages: wdmd warn, close
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 iodelay $dev 77
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test lockspace storage delay, long enough to produce sanlock warning,
echo failure/recovery, recovery by lease release using killpath
echo messages: sanlock check lease warn/fail, kill 100, all pids clear
echo messages: killpath_pause
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 /root/killpath_pause
sleep 22
./clientn 4 iodelay $dev 87
sleep 5
set +x


echo test lockspace storage delay, long enough to produce sanlock warning,
echo failure/recovery, recovery by pid sigterm without killpath
echo messages: sanlock check lease warn/fail, kill 15, dead, all pids clear
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 iodelay $dev 87
sleep 5
set +x


echo test daemon run delay, small enough to have no effect
echo messages: none
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 58
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock warning,
echo but not failure, not long enough for wdmd warn or close
echo messages: sanlock check lease warn
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 68
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock warning,
echo but not failure, long enough for wdmd warn and close
echo messages: sanlock check lease warn
echo messages: wdmd warn, close
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 78
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock
echo failure/recovery, recovery by lease release using killpath
echo messages: sanlock check lease fail, kill 100, all pids clear
echo messages: wdmd warn, close, fail
echo messages: killpath_pause
date
set -x
./clientn 4 start $dev 1 /root/killpath_pause
sleep 22
./clientn 4 delay 88
sleep 5
./clientn 4 resume $dev 1
sleep 5
killall -9 sanlk_client
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock
echo failure/recovery, recovery by pid sigterm without killpath
echo messages: sanlock check lease fail, kill 15, dead, all pids clear
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 88
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock
echo failure/recovery, recovery by pid sigkill after skipping killpath
echo messages: sanlock check lease fail, kill 9, dead, all pids clear
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 /root/killpath_pause
sleep 22
./clientn 4 delay 130
sleep 5
set +x


echo test daemon run delay, long enough to produce sanlock
echo failure/recovery, recovery by pid sigkill without killpath
echo messages: sanlock check lease fail, kill 9, dead, all pids clear
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 130
sleep 5
set +x


echo test daemon run delay, long enough to produce watchdog firing
echo messages: wdmd warn, close, fail
date
set -x
./clientn 4 start $dev 1 none
sleep 22
./clientn 4 delay 140
echo should not get here


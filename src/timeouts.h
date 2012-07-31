/*
 * Copyright 2010-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

/*
 * Example of watchdog behavior when host_id renewals fail, assuming
 * that sanlock cannot successfully kill the pids it is supervising that
 * depend on the given host_id.
 *
 * 
 * Using these values in the example
 * wdmd test interval           = 10 (defined in wdmd/main.c)
 * watchdog_fire_timeout        = 60 (constant)
 * io_timeout_seconds           = 10 (defined by us)
 * id_renewal_seconds           = 20 (= delta_renew_max = 2 * io_timeout_seconds)
 * id_renewal_fail_seconds      = 80 (= 4 * delta_renew_max = 8 * io_timeout_seconds)
 * host_dead_seconds            = 140 (id_renewal_fail_seconds + watchdog_fire_timeout)
 *
 *   T  time in seconds
 *
 *   0: sanlock renews host_id on disk
 *      sanlock calls wdmd_test_live(0, 80) [0 + 80]
 *      wdmd test_client sees now 0 < expire 80 ok -> keepalive
 *
 *  10: wdmd test_client sees now 10 < expire 80 ok -> keepalive
 *
 *  20: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(20, 100) [20 + 80]
 *      wdmd test_client sees now 20 < expire 100 or 80 ok -> keepalive
 *
 *  30: wdmd test_client sees now 30 < expire 100 ok -> keepalive
 *
 *  40: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(40, 120) [40 + 80]
 *      wdmd test_client sees now 40 < expire 120 or 100 ok -> keepalive
 *
 *  50: wdmd test_client sees now 50 < expire 120 ok -> keepalive
 *
 *  all normal until 59
 *  ---------------------------------------------------------
 *  problems begin at 60
 *
 *  60: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 60 < expire 120 ok -> keepalive
 *
 *  70: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 70 < expire 120 ok -> keepalive
 *
 *  80: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 80 < expire 120 ok -> keepalive
 *
 *  90: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 90 < expire 120 ok -> keepalive
 *
 * 100: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 100 < expire 120 ok -> keepalive
 *
 * 110: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 110 < expire 120 ok -> keepalive
 *
 * 120: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      sanlock enters recovery mode and starts killing pids
 *      wdmd test_client sees now 120 >= expire 120 fail -> no keepalive
 *      wdmd starts logging error messages every 10 sec
 *
 *      . /dev/watchdog will fire at last keepalive + watchdog_fire_timeout =
 *        T110 + 60 = T170
 *      . host_id will expire at
 *        last disk renewal ok + id_renewal_fail_seconds + watchdog_fire_timeout
 *        T40 + 80 + 60 = T180
 *        (aka last disk renewal ok + host_dead_seconds, T40 + 140 = T180)
 *      . the wdmd test at T110 could have been at T119, so wdmd would have
 *        seen the client unexpired/ok and done keepalive at 119 just before the
 *        expiry at 120, which would lead to /dev/watchdog firing at 119+60 = T179
 *      . so, the watchdog could fire as early as T170 or as late as T179, but
 *        the host_id will not expire until T180
 *
 * 130: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 130 > expire 120 fail -> no keepalive
 *
 * 140: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 140 > expire 120 fail -> no keepalive
 *
 * 150: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 150 > expire 120 fail -> no keepalive
 *
 * 160: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 160 > expire 120 fail -> no keepalive
 *
 * 170: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 170 > expire 120 fail -> no keepalive
 *      /dev/watchdog fires because last keepalive was T110, 60 seconds ago
 *      (earliest possible /dev/watchdog firing due to wdmd checking expiry just
 *      after sanlock calls wdmd_test_live at T110 and just after the expiry at T120)
 *
 * 179: (latest possible /dev/watchdog firing due to wdmd checking expiry just
 *       before the expiry at T119)
 *
 * 180: another host can acquire leases held by host_id.
 *      This is host_dead_seconds (140) after the last successful renewal (T40)
 */

/*
 * Example of watchdog behavior when host_id renewals fail, assuming
 * that sanlock cannot successfully kill the pids it is supervising that
 * depend on the given host_id.
 *
 *
 * Using these values in the example
 * wdmd test interval           = 10 (defined in wdmd/main.c)
 * watchdog_fire_timeout        = 60 (constant)
 * io_timeout_seconds           = 20 (defined by us)
 * id_renewal_seconds           = 40 (= delta_renew_max = 2 * io_timeout_seconds)
 * id_renewal_fail_seconds      = 160 (= 4 * delta_renew_max = 8 * io_timeout_seconds)
 * host_dead_seconds            = 220 (id_renewal_fail_seconds + watchdog_fire_timeout)
 *
 *   T  time in seconds
 *
 *   0: sanlock renews host_id on disk
 *      sanlock calls wdmd_test_live(0, 160) [0 + 160]
 *      wdmd test_client sees now 0 < expire 160 ok -> keepalive
 *
 *  10: wdmd test_client sees now < expire 160 ok -> keepalive
 *  20: wdmd test_client sees now < expire 160 ok -> keepalive
 *  30: wdmd test_client sees now < expire 160 ok -> keepalive
 *
 *  40: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(40, 200) [40 + 160]
 *      wdmd test_client sees now 40 < expire 200 or 160 ok -> keepalive
 *
 *  50: wdmd test_client sees now < expire 200 ok -> keepalive
 *  60: wdmd test_client sees now < expire 200 ok -> keepalive
 *  70: wdmd test_client sees now < expire 200 ok -> keepalive
 *
 *  80: sanlock renews host_id on disk ok
 *      sanlock calls wdmd_test_live(80, 240) [80 + 160]
 *      wdmd test_client sees now 80 < expire 240 or 200 ok -> keepalive
 *
 *  90: wdmd test_client sees now < expire 240 ok -> keepalive
 * 100: wdmd test_client sees now < expire 240 ok -> keepalive
 * 110: wdmd test_client sees now < expire 240 ok -> keepalive
 *
 *  all normal until 119
 *  ---------------------------------------------------------
 *  problems begin at 120
 *
 * 120: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now 120 < expire 240 ok -> keepalive
 *
 * 130: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 140: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 150: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 160: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 170: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 180: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 190: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 200: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 210: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 220: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 * 230: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now < expire 240 ok -> keepalive
 *
 * 240: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      sanlock enters recovery mode and starts killing pids
 *      wdmd test_client sees now 240 >= expire 240 fail -> no keepalive
 *      wdmd starts logging error messages every 10 sec
 *
 *      . /dev/watchdog will fire at last keepalive + watchdog_fire_timeout =
 *        T230 + 60 = T290
 *      . host_id will expire at
 *        last disk renewal ok + id_renewal_fail_seconds + watchdog_fire_timeout
 *        T80 + 160 + 60 = T300
 *        (aka last disk renewal ok + host_dead_seconds, T80 + 220 = T300)
 *      . the wdmd test at T230 could have been at T239, so wdmd would have
 *        seen the client unexpired/ok and done keepalive at 239 just before the
 *        expiry at 240, which would lead to /dev/watchdog firing at 239+60 = T299
 *      . so, the watchdog could fire as early as T290 or as late as T299, but
 *        the host_id will not expire until T300
 *
 * 250: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now > expire 240 fail -> no keepalive
 * 260: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now > expire 240 fail -> no keepalive
 * 270: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now > expire 240 fail -> no keepalive
 * 280: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now > expire 240 fail -> no keepalive
 * 290: sanlock fails to renew host_id on disk -> no wdmd_test_live
 *      wdmd test_client sees now > expire 240 fail -> no keepalive
 *      /dev/watchdog fires because last keepalive was T230, 60 seconds ago
 *      (earliest possible /dev/watchdog firing due to wdmd checking expiry
 *      just after sanlock calls wdmd_test_live at T230 and just after expiry at T240)
 *
 * 299: (latest possible /dev/watchdog firing due to wdmd checking expiry just
 *      before the expiry at T239)	
 *
 * 300: another host can acquire leases held by host_id
 *      This is host_dead_seconds (220) after last successful renewal (T80)
 */


/*
 * killing pids
 *
 * From the time sanlock enters recovery mode and starts killing pids at T120,
 * until /dev/watchdog fires between T170 and T179, we need to attempt to
 * gracefully kill pids for some time, and then leave around 10 seconds to
 * escalate to SIGKILL and clean up leases from the exited pids.
 *
 * Working backward from the earlier watchdog firing at T170, leaving 10 seconds
 * for SIGKILL to succeed, we need to begin SIGKILL at T160.  This means we
 * have from T120 to T160 to allow graceful kill to complete.  So, kill_count_grace
 * should be set to 40 by default (T120 to T160).
 *
 * T40: last successful disk renewal
 * T120 - T159: graceful pid shutdown (40 sec)
 * T160 - T169: SIGKILL once per second (10 sec)
 * T170 - T179: watchdog fires sometime (SIGKILL continues)
 * T180: other hosts acquire our leases
 *
 * The interval between each kill count/attempt is approx 1 sec,
 * so kill_count/kill_count_grace/kill_count_max serve as both
 * the number/count of attempts and the number of seconds spent
 * using that kind of termination.
 */

 
/*
 * "delta" refers to timed based leases described in Chockler/Malkhi that
 * we use for host_id ownership.
 *
 * "paxos" refers to disk paxos based leases described in Lamport that
 * we use for resource (vm) ownership.
 *
 * "free" refers to a lease (either type) that is not owned by anyone
 *
 * "held" refers to a lease (either type) that was owned by a host that
 * failed, so it was not released/freed.
 . (if a renewal fails we always attempt another renewal immediately)
 *
 * "max" refers to the maximum time that a successful acquire/renew can
 * take, assuming that every io operation takes the max allowable time
 * (io_timeout_seconds)
 *
 * "min" refers to the minimum time that a successful acquire/renew can
 * take, assuming that every io operation completes immediately, in
 * effectively zero time
 *
 *
 * io_timeout_seconds: defined by us
 *
 * id_renewal_seconds: defined by us
 *
 * id_renewal_fail_seconds: defined by us
 *
 * watchdog_fire_timeout: /dev/watchdog will fire without being petted this long
 * = 60 constant
 *
 * host_dead_seconds: the length of time from the last successful host_id
 * renewal until that host is killed by its watchdog.
 * = id_renewal_fail_seconds + watchdog_fire_timeout
 *
 * delta_large_delay: from the algorithm
 * = id_renewal_seconds + (6 * io_timeout_seconds)
 *
 * delta_short_delay: from the algorithm
 * = 2 * io_timeout_seconds
 *
 * delta_acquire_held_max: max time it can take to successfully
 * acquire a non-free delta lease
 * = io_timeout_seconds (read) +
 *   max(delta_large_delay, host_dead_seconds) +
 *   io_timeout_seconds (read) +
 *   io_timeout_seconds (write) +
 *   delta_short_delay +
 *   io_timeout_seconds (read)
 *
 * delta_acquire_held_min: min time it can take to successfully
 * acquire a non-free delta lease
 * = max(delta_large_delay, host_dead_seconds)
 *
 * delta_acquire_free_max: max time it can take to successfully
 * acquire a free delta lease.
 * = io_timeout_seconds (read) +
 *   io_timeout_seconds (write) +
 *   delta_short_delay +
 *   io_timeout_seconds (read)
 *
 * delta_acquire_free_min: min time it can take to successfully
 * acquire a free delta lease.
 * = delta_short_delay
 *
 * delta_renew_max: max time it can take to successfully
 * renew a delta lease.
 * = io_timeout_seconds (read) +
 *   io_timeout_seconds (write)
 *
 * delta_renew_min: min time it can take to successfully
 * renew a delta lease.
 * = 0
 *
 * paxos_acquire_held_max: max time it can take to successfully
 * acquire a non-free paxos lease, uncontended.
 * = io_timeout_seconds (read leader) +
 *   host_dead_seconds +
 *   io_timeout_seconds (read leader) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write leader)
 *
 * paxos_acquire_held_min: min time it can take to successfully
 * acquire a non-free paxos lease, uncontended.
 * = host_dead_seconds
 *
 * paxos_acquire_free_max: max time it can take to successfully
 * acquire a free paxos lease, uncontended.
 * = io_timeout_seconds (read leader) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write dblock) +
 *   io_timeout_seconds (read dblocks) +
 *   io_timeout_seconds (write leader)
 *
 * paxos_acquire_free_min: min time it can take to successfully
 * acquire a free paxos lease, uncontended.
 * = 0
 *
 *
 * How to configure the combination of related timeouts defined by us:
 * io_timeout_seconds
 * id_renewal_seconds
 * id_renewal_fail_seconds
 *
 * Here's one approach that seems to produce sensible sets of numbers:
 *
 * io_timeout_seconds = N
 * . max time one io can take
 *
 * delta_renew_max = 2N
 * . max time one renewal can take
 *
 * id_renewal_seconds = delta_renew_max (2N)
 * . delay this long after renewal success before next renew attempt begins
 * . this will be the difference between two successive renewal timestamps
 *   when io times are effectively 0
 * . there's no particular reason for it to be 2N exactly
 * . if a successful renewal takes the max possible time (delta_renew_max),
 *   then the next renewal attempt will begin right away
 * . (if a renewal fails we always attempt another renewal immediately)
 *
 * id_renewal_fail_seconds = 4 * delta_renew_max (8N)
 * . time from last successful renewal until recovery begins
 * . allows for three consecutive max len renewal failures, i.e.
 *   id_renewal_seconds + (3 * delta_renew_max)
 *
 * id_renewal_warn_seconds = 3 * delta_renew_max (6N)
 * . time from last successful renewal until warning about renewal length
 * . allows for two consecutive max len renewal failues
 *
 * T		time in seconds
 * 0		renewal ok
 * 2N		renewal attempt begin
 * 4N		renewal attempt fail1 (each io takes max time)
 * 4N		renewal attempt begin
 * 6N		renewal attempt fail2 (each io takes max time)
 * 6N		renewal attempt begin
 * 8N		renewal attempt fail3 (each io takes max time)
 * 8N		recovery begins (pids killed)
 *
 * If ios don't take the max len (delta_renew_max), this just
 * gives us more attempts to renew before recovery begins.
 *
 * io_timeout_seconds        N    5  10  20
 * id_renewal_seconds       2N   10  20  40
 * id_renewal_fail_seconds  8N   40  80 160
 *
 *  5 sec io timeout: fast storage io perf
 * 10 sec io timeout: normal storage io perf
 * 20 sec io timeout: slow storage io perf
 *
 * [We could break down these computations further by adding a variable
 * F = number of full len renewal failures allowed before recovery
 * begins.  Above F is fixed at 3, but we may want to vary it to be
 * 2 or 4.]
 *
 *                             fast norm slow
 * watchdog_fire_timeout         60   60   60
 *
 * io_timeout_seconds             5   10   20
 * id_renewal_seconds            10   20   40
 * id_renewal_fail_seconds       40   80  160
 * id_renewal_warn_seconds       30   60  120
 *
 * host_dead_seconds            100  140  220
 * delta_large_delay             40   80  160
 * delta_short_delay             10   20   40
 * delta_acquire_held_max       130  200  340
 * delta_acquire_held_min       100  140  220
 * delta_acquire_free_max        25   50  100
 * delta_acquire_free_min        10   20   40
 * delta_renew_max               10   20   40
 * delta_renew_min                0    0    0
 * paxos_acquire_held_max       135  210  360
 * paxos_acquire_held_min       100  140  220
 * paxos_acquire_free_max        30   60  120
 * paxos_acquire_free_min         0    0    0
 */

/*
 * Why does delta_acquire use max(delta_large_delay, host_dead_seconds) instead
 * of just delta_large_delay as specified in the algorithm?
 *
 * 1. the time based lease algorithm uses delta_large_delay to determine that a
 * host is failed, but we want to be more certain the host is dead based on its
 * watchdog firing, and we know the watchdog has fired after host_dead_seconds.
 *
 * 2. if a delta lease can be acquired and released (freed) before
 * host_dead_seconds, that could allow the paxos leases of a failed host to be
 * acquired by someone else before host_dead_seconds (and before the failed
 * host is really dead), because acquiring a held paxos lease depends on the
 * delta lease of the failed owner not changing for host_dead_seconds.
 * We cannot allow a host to acquire another failed host's paxos lease before
 * host_dead_seconds.
 *
 * 3. ios can't be reliably canceled and never really time out; an io is only
 * really dead when the machine is dead/reset or storage access is cut off.
 * The delta lease algorithm expects real io timeouts.
 *
 * So, the delay is really meant to represent the time until we are certain a
 * host is safely gone and will no longer write, and for sanlock that means
 * until the watchdog has reset it.
 */


See https://pagure.io/sanlock

From sanlock(8) at sanlock.git/src/sanlock.8

```
SANLOCK(8)                  System Manager's Manual                 SANLOCK(8)

NAME
       sanlock - shared storage lock manager

SYNOPSIS
       sanlock [COMMAND] [ACTION] ...

DESCRIPTION
       sanlock  is  a lock manager built on shared storage.  Hosts with access
       to the storage can perform locking.   An  application  running  on  the
       hosts  is  given  a small amount of space on the shared block device or
       file, and uses sanlock for its  own  application-specific  synchroniza‐
       tion.   Internally,  the  sanlock  daemon manages locks using two disk-
       based lease algorithms: delta leases and paxos leases.

       · delta leases are slow to acquire and demand  regular  i/o  to  shared
         storage.   sanlock  only  uses them internally to hold a lease on its
         "host_id" (an integer host identifier from 1-2000).  They prevent two
         hosts  from using the same host identifier.  The delta lease renewals
         also indicate if a host is alive.  ("Light-Weight Leases for Storage-
         Centric Coordination", Chockler and Malkhi.)

       · paxos  leases are fast to acquire and sanlock makes them available to
         applications as general purpose  resource  leases.   The  disk  paxos
         algorithm uses host_id's internally to represent different hosts, and
         the owner of a paxos lease.  delta leases  provide  unique  host_id's
         for  implementing  paxos  leases, and delta lease renewals serve as a
         proxy for paxos lease renewal.  ("Disk Paxos", Eli Gafni  and  Leslie
         Lamport.)

       Externally, the sanlock daemon exposes a locking interface through lib‐
       sanlock in terms of "lockspaces" and "resources".   A  lockspace  is  a
       locking  context that an application creates for itself on shared stor‐
       age.  When the application on each host  is  started,  it  "joins"  the
       lockspace.  It can then create "resources" on the shared storage.  Each
       resource represents an application-specific  entity.   The  application
       can acquire and release leases on resources.

       To use sanlock from an application:

       · Allocate  shared  storage for an application, e.g. a shared LUN or LV
         from a SAN, or files from NFS.

       · Provide the storage to the application.

       · The application  uses  this  storage  with  libsanlock  to  create  a
         lockspace and resources for itself.

       · The application joins the lockspace when it starts.

       · The application acquires and releases leases on resources.

       How lockspaces and resources translate to delta leases and paxos leases
       within sanlock:

       Lockspaces

       · A lockspace is based on delta leases held  by  each  host  using  the
         lockspace.

       · A  lockspace  is  a series of 2000 delta leases on disk, and requires
         1MB of storage.

       · A lockspace can support up to 2000 concurrent hosts  using  it,  each
         using a different delta lease.

       · Applications  can  i)  create,  ii)  join and iii) leave a lockspace,
         which corresponds to i) initializing the set of delta leases on disk,
         ii)  acquiring  one  of the delta leases and iii) releasing the delta
         lease.

       · When a lockspace is created, a unique lockspace name and  disk  loca‐
         tion is provided by the application.

       · When a lockspace is created/initialized, sanlock formats the sequence
         of 2000 on-disk delta lease structures on  the  file  or  disk,  e.g.
         /mnt/leasefile (NFS) or /dev/vg/lv (SAN).

       · The  2000  individual  delta  leases in a lockspace are identified by
         number: 1,2,3,...,2000.

       · Each delta lease is a 512 byte sector in the 1MB lockspace, offset by
         its  number,  e.g. delta lease 1 is offset 0, delta lease 2 is offset
         512, delta lease 2000 is offset 1023488.

       · When an application joins a lockspace, it must specify the  lockspace
         name,  the  lockspace  location  on  shared  disk/file, and the local
         host's host_id.  sanlock then acquires the delta lease  corresponding
         to  the  host_id,  e.g. joining the lockspace with host_id 1 acquires
         delta lease 1.

       · The terms delta lease, lockspace lease, and host_id  lease  are  used
         interchangably.

       · sanlock  acquires  a delta lease by writing the host's unique name to
         the delta lease disk sector, reading it back after a delay, and veri‐
         fying it is the same.

       · If  a  unique host name is not specified, sanlock generates a uuid to
         use as the host's name.  The delta lease algorithm depends  on  hosts
         using unique names.

       · The  application  on  each  host  should  be configured with a unique
         host_id, where the host_id is an integer 1-2000.

       · If hosts are misconfigured and have the same host_id, the delta lease
         algorithm is designed to detect this conflict, and only one host will
         be able to acquire the delta lease for that host_id.

       · A delta lease ensures that a lockspace host_id is  being  used  by  a
         single host with the unique name specified in the delta lease.

       · Resolving  delta  lease  conflicts  is slow, because the algorithm is
         based on waiting and watching for some time for other hosts to  write
         to  the  same  delta  lease sector.  If multiple hosts try to use the
         same delta lease, the delay is increased substantially.   So,  it  is
         best  to configure applications to use unique host_id's that will not
         conflict.

       · After sanlock acquires a delta lease, the lease must be renewed until
         the  application leaves the lockspace (which corresponds to releasing
         the delta lease on the host_id.)

       · sanlock renews delta leases every 20 seconds (by default) by  writing
         a new timestamp into the delta lease sector.

       · When a host acquires a delta lease in a lockspace, it can be referred
         to as "joining" the lockspace.  Once it has joined the lockspace,  it
         can use resources associated with the lockspace.

       Resources

       · A  lockspace  is  a  context  for  resources  that  can be locked and
         unlocked by an application.

       · sanlock uses paxos leases to  implement  leases  on  resources.   The
         terms paxos lease and resource lease are used interchangably.

       · A paxos lease exists on shared storage and requires 1MB of space.  It
         contains a unique resource name and the name of the lockspace.

       · An application assigns its own meaning to a sanlock resource and  the
         leases  on it.  A sanlock resource could represent some shared object
         like a file, or some unique role among the hosts.

       · Resource leases are associated with a specific lockspace and can only
         be  used by hosts that have joined that lockspace (they are holding a
         delta lease on a host_id in that lockspace.)

       · An  application  must  keep  track  of  the  disk  locations  of  its
         lockspaces  and  resources.  sanlock does not maintain any persistent
         index or directory of lockspaces or resources that have been  created
         by  applications,  so  applications  need to remember where they have
         placed their own leases (which files or disks and offsets).

       · sanlock does not renew paxos leases  directly  (although  it  could).
         Instead,  the  renewal of a host's delta lease represents the renewal
         of all that host's paxos  leases  in  the  associated  lockspace.  In
         effect,  many  paxos  lease  renewals are factored out into one delta
         lease renewal.  This reduces i/o when many paxos leases are used.

       · The disk paxos algorithm allows multiple  hosts  to  all  attempt  to
         acquire  the same paxos lease at once, and will produce a single win‐
         ner/owner of the resource lease.  (Shared resource  leases  are  also
         possible in addition to the default exclusive leases.)

       · The  disk paxos algorithm involves a specific sequence of reading and
         writing the sectors of the paxos lease disk area.  Each  host  has  a
         dedicated  512  byte  sector  in  the  paxos lease disk area where it
         writes its own "ballot", and each host reads the entire disk area  to
         see the ballots of other hosts.  The first sector of the disk area is
         the "leader record" that holds the result of the last  paxos  ballot.
         The winner of the paxos ballot writes the result of the ballot to the
         leader record (the winner of the ballot  may  have  selected  another
         contending host as the owner of the paxos lease.)

       · After  a paxos lease is acquired, no further i/o is done in the paxos
         lease disk area.

       · Releasing the paxos lease involves writing a single sector  to  clear
         the current owner in the leader record.

       · If  a  host  holding  a paxos lease fails, the disk area of the paxos
         lease still indicates that the paxos lease is  owned  by  the  failed
         host.  If another host attempts to acquire the paxos lease, and finds
         the lease is held by another host_id, it will check the  delta  lease
         of that host_id.  If the delta lease of the host_id is being renewed,
         then the paxos lease is owned and cannot be acquired.  If  the  delta
         lease  of  the  owner's  host_id has expired, then the paxos lease is
         expired and can be taken (by going  through  the  paxos  lease  algo‐
         rithm.)

       · The  "interaction" or "awareness" between hosts of each other is lim‐
         ited to the case where they attempt to acquire the same paxos  lease,
         and need to check if the referenced delta lease has expired or not.

       · When  hosts  do  not attempt to lock the same resources concurrently,
         there is no host interaction or awareness.  The state or  actions  of
         one host have no effect on others.

       · To  speed  up checking delta lease expiration (in the case of a paxos
         lease conflict), sanlock keeps track of past renewals of other  delta
         leases in the lockspace.

       Expiration

       · If  a  host  fails to renew its delta lease, e.g. it looses access to
         the storage, its delta lease will eventually expire and another  host
         will be able to take over any resource leases held by the host.  san‐
         lock must ensure that the application on two different hosts  is  not
         holding and using the same lease concurrently.

       · When  sanlock has failed to renew a delta lease for a period of time,
         it will begin taking measures to stop local processes  (applications)
         from using any resource leases associated with the expiring lockspace
         delta lease.  sanlock enters this "recovery mode" well ahead  of  the
         time  when  another  host  could  take over the locally owned leases.
         sanlock must have sufficient time to stop all  local  processes  that
         are using the expiring leases.

       · sanlock  uses  three  methods  to stop local processes that are using
         expiring leases:

         1. Graceful shutdown.  sanlock will  execute  a  "graceful  shutdown"
         program that the application previously specified for this case.  The
         shutdown program tells the  application  to  shut  down  because  its
         leases  are  expiring.   The application must respond by stopping its
         activities and releasing its leases (or  exit).   If  an  application
         does  not  specify a graceful shutdown program, sanlock sends SIGTERM
         to the process instead.  The process must release its leases or  exit
         in  a  prescribed amount of time (see -g), or sanlock proceeds to the
         next method of stopping.

         2. Forced shutdown.  sanlock will send SIGKILL to processes using the
         expiring  leases.   The processes have a fixed amount of time to exit
         after receiving SIGKILL.  If any do not exit in  this  time,  sanlock
         will proceed to the next method.

         3.  Host  reset.   sanlock will trigger the host's watchdog device to
         forcibly reset it.  sanlock  carefully  manages  the  timing  of  the
         watchdog  device so that it fires shortly before any other host could
         take over the resource leases held by local processes.

       Failures

       If a process holding resource leases fails or exits  without  releasing
       its  leases,  sanlock  will  release  the  leases  for it automatically
       (unless persistent resource leases were used.)

       If the sanlock daemon cannot renew a lockspace delta lease for  a  spe‐
       cific  period  of  time  (see Expiration), sanlock will enter "recovery
       mode" where it attempts to  stop  and/or  kill  any  processes  holding
       resource  leases  in  the  expiring lockspace.  If the processes do not
       exit in time, sanlock will force the host to be reset using  the  local
       watchdog device.

       If  the  sanlock  daemon crashes or hangs, it will not renew the expiry
       time of the per-lockspace connections it had to the wdmd daemon.   This
       will  lead to the expiration of the local watchdog device, and the host
       will be reset.

       Watchdog

       sanlock uses the wdmd(8) daemon to access /dev/watchdog.   wdmd  multi‐
       plexes  multiple  timeouts  onto  the  single  watchdog timer.  This is
       required because delta leases for each lockspace are renewed and expire
       independently.

       sanlock  maintains  a  wdmd  connection  for each lockspace delta lease
       being renewed.  Each connection has an expiry time for some seconds  in
       the future.  After each successful delta lease renewal, the expiry time
       is renewed for the associated wdmd connection.  If wdmd finds any  con‐
       nection  expired,  it  will  not  renew the /dev/watchdog timer.  Given
       enough successive failed renewals, the watchdog device  will  fire  and
       reset  the host.  (Given the multiplexing nature of wdmd, shorter over‐
       lapping renewal failures from multiple lockspaces could cause  spurious
       watchdog firing.)

       The direct link between delta lease renewals and watchdog renewals pro‐
       vides a predictable watchdog firing time based on delta  lease  renewal
       timestamps  that  are visible from other hosts.  sanlock knows the time
       the watchdog on another host has fired based on the delta  lease  time.
       Furthermore,  if the watchdog device on another host fails to fire when
       it should, the continuation of delta lease renewals from the other host
       will  make  this  evident  and prevent leases from being taken from the
       failed host.

       If sanlock is able  to  stop/kill  all  processing  using  an  expiring
       lockspace,  the  associated  wdmd  connection  for  that  lockspace  is
       removed.  The expired wdmd connection will no longer block  /dev/watch‐
       dog renewals, and the host should avoid being reset.

       Storage

       On  devices  with 512 byte sectors, lockspaces and resources are 1MB in
       size.  On devices with 4096 byte sectors, lockspaces and resources  are
       8MB  in size.  sanlock uses 512 byte sectors when shared files are used
       in place of shared block devices.  Offsets of leases or resources  must
       be multiples of 1MB/8MB according to the sector size.

       Using  sanlock  on shared block devices that do host based mirroring or
       replication is not likely to work correctly.   When  using  sanlock  on
       shared files, all sanlock io should go to one file server.

       Example

       This  is an example of creating and using lockspaces and resources from
       the command line.  (Most applications would use sanlock through libsan‐
       lock rather than through the command line.)

       1.  Allocate shared storage for sanlock leases.

           This  example assumes 512 byte sectors on the device, in which case
           the lockspace needs 1MB and each resource needs 1MB.

           # vgcreate vg /dev/sdb
           # lvcreate -n leases -L 1GB vg

       2.  Start sanlock on all hosts.

           The -w 0 disables use of the watchdog for testing.

           # sanlock daemon -w 0

       3.  Start a dummy application on all hosts.

           This sanlock command registers with sanlock, then execs  the  sleep
           command  which  inherits the registered fd.  The sleep process acts
           as the dummy application.  Because the sleep process is  registered
           with sanlock, leases can be acquired for it.

           # sanlock client command -c /bin/sleep 600 &

       4.  Create a lockspace for the application (from one host).

           The lockspace is named "test".

           # sanlock client init -s test:0:/dev/test/leases:0

       5.  Join the lockspace for the application.

           Use a unique host_id on each host.

           host1:
           # sanlock client add_lockspace -s test:1/dev/vg/leases:0
           host2:
           # sanlock client add_lockspace -s test:2/dev/vg/leases:0

       6.  Create two resources for the application (from one host).

           The  resources  are  named  "RA" and "RB".  Offsets are used on the
           same device as the lockspace.  Different LVs or files could also be
           used.

           # sanlock client init -r test:RA:/dev/vg/leases:1048576
           # sanlock client init -r test:RB:/dev/vg/leases:2097152

       7.  Acquire resource leases for the application on host1.

           Acquire an exclusive lease (the default) on the first resource, and
           a shared lease (SH) on the second resource.

           # export P=`pidof sleep`
           # sanlock client acquire -r test:RA:/dev/vg/leases:1048576 -p $P
           # sanlock client acquire -r test:RB:/dev/vg/leases:2097152:SH -p $P

       8.  Acquire resource leases for the application on host2.

           Acquiring the exclusive lease  on  the  first  resource  will  fail
           because  it  is  held  by host1.  Acquiring the shared lease on the
           second resource will succeed.

           # export P=`pidof sleep`
           # sanlock client acquire -r test:RA:/dev/vg/leases:1048576 -p $P
           # sanlock client acquire -r test:RB:/dev/vg/leases:2097152:SH -p $P

       9.  Release resource leases for the application on both hosts.

           The sleep pid could also be killed, which will result in  the  san‐
           lock daemon releasing its leases when it exits.

           # sanlock client release -r test:RA:/dev/vg/leases:1048576 -p $P
           # sanlock client release -r test:RB:/dev/vg/leases:2097152 -p $P

       10. Leave the lockspace for the application.

           host1:
           # sanlock client rem_lockspace -s test:1/dev/vg/leases:0
           host2:
           # sanlock client rem_lockspace -s test:2/dev/vg/leases:0

       11. Stop sanlock on all hosts.

           # sanlock shutdown

OPTIONS
       COMMAND can be one of three primary top level choices

       sanlock daemon start daemon
       sanlock client send request to daemon (default command if none given)
       sanlock direct access storage directly (no coordination with daemon)

   Daemon Command
       sanlock daemon [options]

       -D no fork and print all logging to stderr

       -Q 0|1 quiet error messages for common lock contention

       -R 0|1 renewal debugging, log debug info for each renewal

       -L pri write logging at priority level and up to logfile (-1 none)

       -S pri write logging at priority level and up to syslog (-1 none)

       -U uid user id

       -G gid group id

       -t num max worker threads

       -g sec seconds for graceful recovery

       -w 0|1 use watchdog through wdmd

       -h 0|1 use high priority (RR) scheduling

       -l num use mlockall (0 none, 1 current, 2 current and future)

       -b sec seconds a host id bit will remain set in delta lease bitmap

       -e str local host name used in delta leases

   Client Command
       sanlock client action [options]

       sanlock client status

       Print processes, lockspaces, and resources being managed by the sanlock
       daemon.  Add -D to show extra internal  daemon  status  for  debugging.
       Add  -o  p  to  show  resources  by  pid,  or -o s to show resources by
       lockspace.

       sanlock client host_status

       Print state of host_id delta  leases  read  during  the  last  renewal.
       State  of  all  lockspaces  is shown (use -s to select one).  Add -D to
       show extra internal daemon status for debugging.

       sanlock client gets

       Print lockspaces being managed by the sanlock  daemon.   The  LOCKSPACE
       string  will  be  followed  by ADD or REM if the lockspace is currently
       being added or removed.  Add -h 1 to also show hosts in each lockspace.

       sanlock client renewal -s LOCKSPACE

       Print a history of renewals with timing details.  See the Renewal  his‐
       tory section below.

       sanlock client log_dump

       Print the sanlock daemon internal debug log.

       sanlock client shutdown

       Ask  the  sanlock daemon to exit.  Without the force option (-f 0), the
       command will be ignored if any lockspaces exist.  With the force option
       (-f  1), any registered processes will be killed, their resource leases
       released, and lockspaces removed.  With the wait  option  (-w  1),  the
       command  will  wait for a result from the daemon indicating that it has
       shut down and is exiting, or cannot shut down because lockspaces  exist
       (command fails).

       sanlock client init -s LOCKSPACE

       Tell  the  sanlock  daemon  to  initialize a lockspace on disk.  The -o
       option can be used to specify the io  timeout  to  be  written  in  the
       host_id leases.  (Also see sanlock direct init.)

       sanlock client init -r RESOURCE

       Tell  the sanlock daemon to initialize a resource lease on disk.  (Also
       see sanlock direct init.)

       sanlock client read -s LOCKSPACE

       Tell the sanlock daemon to  read  a  lockspace  from  disk.   Only  the
       LOCKSPACE  path and offset are required.  If host_id is zero, the first
       record at offset (host_id 1) is used.  The complete  LOCKSPACE  and  io
       timeout are printed.

       sanlock client read -r RESOURCE

       Tell  the  sanlock daemon to read a resource lease from disk.  Only the
       RESOURCE path and  offset  are  required.   The  complete  RESOURCE  is
       printed.  (Also see sanlock direct read_leader.)

       sanlock client align -s LOCKSPACE

       Tell  the  sanlock  daemon to report the required lease alignment for a
       storage path.  Only path is used from the LOCKSPACE argument.

       sanlock client add_lockspace -s LOCKSPACE

       Tell the sanlock  daemon  to  acquire  the  specified  host_id  in  the
       lockspace.   This will allow resources to be acquired in the lockspace.
       The -o option can be used to specify the io timeout  of  the  acquiring
       host, and will be written in the host_id lease.

       sanlock client inq_lockspace -s LOCKSPACE

       Inquire about the state of the lockspace in the sanlock daemon, whether
       it is being added or removed, or is joined.

       sanlock client rem_lockspace -s LOCKSPACE

       Tell the sanlock  daemon  to  release  the  specified  host_id  in  the
       lockspace.   Any  processes  holding  resource leases in this lockspace
       will be killed, and the resource leases not released.

       sanlock client command -r RESOURCE -c path args

       Register with the sanlock daemon, acquire the specified resource lease,
       and  exec  the  command at path with args.  When the command exits, the
       sanlock daemon will release the lease.  -c must be the final option.

       sanlock client acquire -r RESOURCE -p pid
       sanlock client release -r RESOURCE -p pid

       Tell the sanlock daemon to acquire or release  the  specified  resource
       lease  for  the given pid.  The pid must be registered with the sanlock
       daemon.  acquire  can  optionally  take  a  versioned  RESOURCE  string
       RESOURCE:lver,  where  lver  is  the  version of the lease that must be
       acquired, or fail.

       sanlock client convert -r RESOURCE -p pid

       Tell the sanlock daemon to convert the mode of the  specified  resource
       lease  for the given pid.  If the existing mode is exclusive (default),
       the mode of the lease can be converted to shared with RESOURCE:SH.   If
       the  existing mode is shared, the mode of the lease can be converted to
       exclusive with RESOURCE (no :SH suffix).

       sanlock client inquire -p pid

       Print the resource leases held the given pid.  The  format  is  a  ver‐
       sioned RESOURCE string "RESOURCE:lver" where lver is the version of the
       lease held.

       sanlock client request -r RESOURCE -f force_mode

       Request the owner of a resource do something specified  by  force_mode.
       A  versioned  RESOURCE:lver  string must be used with a greater version
       than is presently held.  Zero lver and force_mode clears the request.

       sanlock client examine -r RESOURCE

       Examine the request record for the currently held  resource  lease  and
       carry out the action specified by the requested force_mode.

       sanlock client examine -s LOCKSPACE

       Examine  requests  for  all resource leases currently held in the named
       lockspace.  Only lockspace_name is used from the LOCKSPACE argument.

       sanlock client set_event -s LOCKSPACE -i host_id -g gen -e num -d num

       Set an event for another host.  When the sanlock daemon next renews its
       delta  lease  for the lockspace it will: set the bit for the host_id in
       its bitmap, and set the generation, event and data values  in  its  own
       delta  lease.   An application that has registered for events from this
       lockspace on the destination host will get the event that has been  set
       when  the  destination  sees  the  event  during  its  next delta lease
       renewal.

       sanlock client set_config -s LOCKSPACE

       Set a configuration value for a lockspace.  Only lockspace_name is used
       from  the  LOCKSPACE  argument.  The USED flag has the same effect on a
       lockspace as a process holding a resource lease  that  will  not  exit.
       The  USED_BY_ORPHANS flag means that an orphan resource lease will have
       the same effect as the USED.
       -u 0|1 Set (1) or clear (0) the USED flag.
       -O 0|1 Set (1) or clear (0) the USED_BY_ORPHANS flag.

   Direct Command
       sanlock direct action [options]

       -o sec io timeout in seconds

       sanlock direct init -s LOCKSPACE
       sanlock direct init -r RESOURCE

       Initialize storage for  2000  host_id  (delta)  leases  for  the  given
       lockspace,  or initialize storage for one resource (paxos) lease.  Both
       options require 1MB of space.  The host_id in the LOCKSPACE  string  is
       not  relevant to initialization, so the value is ignored.  (The default
       of 2000 host_ids  can  be  changed  for  special  cases  using  the  -n
       num_hosts  and -m max_hosts options.)  With -s, the -o option specifies
       the io timeout to be written in the host_id leases.  With -r, the -z  1
       option  invalidates  the  resource  lease  on disk so it cannot be used
       until reinitialized normally.

       sanlock direct read_leader -s LOCKSPACE
       sanlock direct read_leader -r RESOURCE

       Read a leader record from disk and print the fields.  The leader record
       is  the  single sector of a delta lease, or the first sector of a paxos
       lease.

       sanlock direct dump path[:offset[:size]]

       Read disk sectors and print leader records for delta or  paxos  leases.
       Add  -f  1  to  print  the  request record values for paxos leases, and
       host_ids set in delta lease bitmaps.

   LOCKSPACE option string
       -s lockspace_name:host_id:path:offset

       lockspace_name name of lockspace
       host_id local host identifier in lockspace
       path path to storage reserved for leases
       offset offset on path (bytes)

   RESOURCE option string
       -r lockspace_name:resource_name:path:offset

       lockspace_name name of lockspace
       resource_name name of resource
       path path to storage reserved for leases
       offset offset on path (bytes)

   RESOURCE option string with suffix
       -r lockspace_name:resource_name:path:offset:lver

       lver leader version

       -r lockspace_name:resource_name:path:offset:SH

       SH indicates shared mode

   Defaults
       sanlock help shows the default values for the options above.

       sanlock version shows the build version.

OTHER
   Request/Examine
       The first part of making a  request  for  a  resource  is  writing  the
       request  record  of  the  resource  (the  sector  following  the leader
       record).  To make a successful request:

       · RESOURCE:lver must be greater than the lver  presently  held  by  the
         other  host.  This implies the leader record must be read to discover
         the lver, prior to making a request.

       · RESOURCE:lver must be greater than or equal  to  the  lver  presently
         written  to the request record.  Two hosts may write a new request at
         the same time for the same lver, in which case  both  would  succeed,
         but the force_mode from the last would win.

       · The force_mode must be greater than zero.

       · To  unconditionally  clear  the  request  record  (set  both lver and
         force_mode to 0), make request with RESOURCE:0 and force_mode 0.

       The owner of the requested resource will not know of the request unless
       it  is  explicitly  told  to  examine  its  resources via the "examine"
       api/command, or otherwise notfied.

       The second part of making a request is  notifying  the  resource  lease
       owner  that  it  should  examine  the  request  records of its resource
       leases.  The notification will cause the lease owner  to  automatically
       run  the  equivalent  of  "sanlock client examine -s LOCKSPACE" for the
       lockspace of the requested resource.

       The notification is made using a bitmap in each  host_id  delta  lease.
       Each  bit represents each of the possible host_ids (1-2000).  If host A
       wants to notify host B to examine its resources, A sets the bit in  its
       own  bitmap  that  corresponds to the host_id of B.  When B next renews
       its delta lease, it reads the delta leases for  all  hosts  and  checks
       each  bitmap  to see if its own host_id has been set.  It finds the bit
       for its own host_id set  in  A's  bitmap,  and  examines  its  resource
       request  records.   (The  bit  remains  set  in A's bitmap for set_bit‐
       map_seconds.)

       force_mode determines the action the resource lease owner should take:

       · FORCE (1): kill the process holding the  resource  lease.   When  the
         process has exited, the resource lease will be released, and can then
         be acquired by anyone.  The kill signal is  SIGKILL  (or  SIGTERM  if
         SIGKILL is restricted.)

       · GRACEFUL  (2): run the program configured by sanlock_killpath against
         the process holding the resource lease.  If no killpath  is  defined,
         then FORCE is used.

   Persistent and orphan resource leases
       A  resource  lease can be acquired with the PERSISTENT flag (-P 1).  If
       the process holding the lease exits, the lease will  not  be  released,
       but  kept  on  an  orphan  list.   Another local process can acquire an
       orphan lease using the ORPHAN flag (-O 1), or release the orphan  lease
       using  the  ORPHAN  flag  (-O 1).  All orphan leases can be released by
       setting the lockspace name (-s lockspace_name) with no resource name.

   Renewal history
       sanlock saves a limited history of lease renewal  information  in  each
       lockspace.   See sanlock.conf renewal_history_size to set the amount of
       history or to disable (set to 0).

       IO times are measured in delta lease renewal (each delta lease  renewal
       includes one read and one write).

       For each successful renewal, a record is saved that includes:

       · the timestamp written in the delta lease by the renewal

       · the time in milliseconds taken by the delta lease read

       · the time in milliseconds taken by the delta lease write

       Also  counted  and  recorded  are  the  number io timeouts and other io
       errors that occur between successful renewals.

       Two consecutive successful renewals would be recorded as:
       timestamp=5332 read_ms=482 write_ms=5525 next_timeouts=0 next_errors=0
       timestamp=5353 read_ms=99 write_ms=3161 next_timeouts=0 next_errors=0

       Those fields are:

       · timestamp is the value written  into  the  delta  lease  during  that
         renewal.

       · read_ms/write_ms   are   the   milliseconds  taken  for  the  renewal
         read/write ios.

       · next_timeouts are the number of io timeouts that  occured  after  the
         renewal recorded on that line, and before the next successful renewal
         on the following line.

       · next_errors are the number of io errors (not timeouts)  that  occured
         after  renewal  recorded on that line, and before the next successful
         renewal on the following line.

       The command 'sanlock client renewal -s lockspace_name' reports the full
       history  of renewals saved by sanlock, which by default is 180 records,
       about 1 hour of history when using a 20 second renewal interval  for  a
       10 second io timeout.

INTERNALS
   Disk Format
       · This example uses 512 byte sectors.

       · Each  lockspace  is 1MB.  It holds 2000 delta_leases, one per sector,
         supporting up to 2000 hosts.

       · Each paxos_lease is 1MB.  It is used as a lease for one resource.

       · The leader_record structure is used differently by each lease type.

       · To display all leader_record fields, see sanlock direct read_leader.

       · A lockspace is often followed on disk by the paxos_leases used within
         that lockspace, but this layout is not required.

       · The request_record and host_id bitmap are used for requests/events.

       · The mode_block contains the SHARED flag indicating a lease is held in
         the shared mode.

       · In a  lockspace,  the  host  using  host_id  N  writes  to  a  single
         delta_lease in sector N-1.  No other hosts write to this sector.  All
         hosts read all lockspace sectors when renewing their own delta_lease,
         and are able to monitor renewals of all delta_leases.

       · In a paxos_lease, each host has a dedicated sector it writes to, con‐
         taining its own paxos_dblock and mode_block structures.   Its  sector
         is based on its host_id; host_id 1 writes to the dblock/mode_block in
         sector 2 of the paxos_lease.

       · The paxos_dblock structures are used by  the  paxos_lease  algorithm,
         and the result is written to the leader_record.

       0x000000 lockspace foo:0:/path:0

       (There  is  no representation on disk of the lockspace in general, only
       the sequence of specific delta_leases which collectively represent  the
       lockspace.)

       delta_lease foo:1:/path:0
       0x000 0         leader_record         (sector 0, for host_id 1)
                       magic: 0x12212010
                       space_name: foo
                       resource_name: host uuid/name
                       ...
                       host_id bitmap        (leader_record + 256)

       delta_lease foo:2:/path:0
       0x200 512       leader_record         (sector 1, for host_id 2)
                       magic: 0x12212010
                       space_name: foo
                       resource_name: host uuid/name
                       ...
                       host_id bitmap        (leader_record + 256)

       delta_lease foo:3:/path:0
       0x400 1024      leader_record         (sector 2, for host_id 3)
                       magic: 0x12212010
                       space_name: foo
                       resource_name: host uuid/name
                       ...
                       host_id bitmap        (leader_record + 256)

       delta_lease foo:2000:/path:0
       0xF9E00         leader_record         (sector 1999, for host_id 2000)
                       magic: 0x12212010
                       space_name: foo
                       resource_name: host uuid/name
                       ...
                       host_id bitmap        (leader_record + 256)

       0x100000 paxos_lease foo:example1:/path:1048576
       0x000 0         leader_record         (sector 0)
                       magic: 0x06152010
                       space_name: foo
                       resource_name: example1

       0x200 512       request_record        (sector 1)
                       magic: 0x08292011

       0x400 1024      paxos_dblock          (sector 2, for host_id 1)
       0x480 1152      mode_block            (paxos_dblock + 128)

       0x600 1536      paxos_dblock          (sector 3, for host_id 2)
       0x680 1664      mode_block            (paxos_dblock + 128)

       0x800 2048      paxos_dblock          (sector 4, for host_id 3)
       0x880 2176      mode_block            (paxos_dblock + 128)

       0xFA200         paxos_dblock          (sector 2001, for host_id 2000)
       0xFA280         mode_block            (paxos_dblock + 128)

       0x200000 paxos_lease foo:example2:/path:2097152
       0x000 0         leader_record         (sector 0)
                       magic: 0x06152010
                       space_name: foo
                       resource_name: example2

       0x200 512       request_record        (sector 1)
                       magic: 0x08292011

       0x400 1024      paxos_dblock          (sector 2, for host_id 1)
       0x480 1152      mode_block            (paxos_dblock + 128)

       0x600 1536      paxos_dblock          (sector 3, for host_id 2)
       0x680 1664      mode_block            (paxos_dblock + 128)

       0x800 2048      paxos_dblock          (sector 4, for host_id 3)
       0x880 2176      mode_block            (paxos_dblock + 128)

       0xFA200         paxos_dblock          (sector 2001, for host_id 2000)
       0xFA280         mode_block            (paxos_dblock + 128)

   Lease ownership
       Not  shown  in  the  leader_record  structures  above are the owner_id,
       owner_generation and timestamp  fields.   These  are  the  fields  that
       define the lease owner.

       The  delta_lease at sector N for host_id N+1 has leader_record.owner_id
       N+1.  The leader_record.owner_generation is incremented each  time  the
       delta_lease   is   acquired.   When  a  delta_lease  is  acquired,  the
       leader_record.timestamp field is set to the time of the  host  and  the
       leader_record.resource_name  is  set  to  the  unique name of the host.
       When   the   host   renews   the   delta_lease,   it   writes   a   new
       leader_record.timestamp.  When a host releases a delta_lease, it writes
       zero to leader_record.timestamp.

       When a host acquires a  paxos_lease,  it  uses  the  host_id/generation
       value  from  the  delta_lease  it holds in the lockspace.  It uses this
       host_id/generation to identify itself in the paxos_dblock when  running
       the  paxos  algorithm.   The  result  of  the  algorithm is the winning
       host_id/generation - the new owner of  the  paxos_lease.   The  winning
       host_id/generation      are      written     to     the     paxos_lease
       leader_record.owner_id and  leader_record.owner_generation  fields  and
       leader_record.timestamp is set.  When a host releases a paxos_lease, it
       sets leader_record.timestamp to 0.

       When a paxos_lease is free  (leader_record.timestamp  is  0),  multiple
       hosts  may  attempt  to  acquire  it.   The  paxos algorithm, using the
       paxos_dblock structures, will select only one of the hosts as  the  new
       owner, and that owner is written in the leader_record.  The paxos_lease
       will no longer be free (non-zero timestamp).  Other hosts will see this
       and will not attempt to acquire the paxos_lease until it is free again.

       If  a  paxos_lease is owned (non-zero timestamp), but the owner has not
       renewed its delta_lease for a specific length of time, then  the  owner
       value  in the paxos_lease becomes expired, and other hosts will use the
       paxos algorithm to acquire the paxos_lease, and set a new owner.

FILES
       /etc/sanlock/sanlock.conf

SEE ALSO
       wdmd(8)

                                  2015-01-23                        SANLOCK(8)
```

From wdmd(8) at sanlock.git/wdmd/wdmd.8

```
WDMD(8)                     System Manager's Manual                    WDMD(8)

NAME
       wdmd - watchdog multiplexing daemon

SYNOPSIS
       wdmd [OPTIONS]

DESCRIPTION
       This daemon opens /dev/watchdog and allows multiple independent sources
       to detmermine whether each KEEPALIVE is done.  Every test interval  (10
       seconds),  the  daemon  tests  each  source.   If  any  test fails, the
       KEEPALIVE is not done.  In a standard configuration, the watchdog timer
       will  reset  the  system  if no KEEPALIVE is done for 60 seconds ("fire
       timeout").  This means that if a single test fails 5-6  times  in  row,
       the  watchdog  will  fire  and  reset  the  system.  With multiple test
       sources, fewer separate failures back to back can also cause  a  reset,
       e.g.

       T seconds, P pass, F fail
       T00: test1 P, test2 P, test3 P: KEEPALIVE done
       T10: test1 F, test2 F, test3 P: KEEPALIVE skipped
       T20: test1 F, test2 P, test3 P: KEEPALIVE skipped
       T30: test1 P, test2 F, test3 P: KEEPALIVE skipped
       T40: test1 P, test2 P, test3 F: KEEPALIVE skipped
       T50: test1 F, test2 F, test3 P: KEEPALIVE skipped
       T60: test1 P, test2 F, test3 P: KEEPALIVE skipped
       T60: watchdog fires, system resets

       (Depending  on timings, the system may be reset sometime shortly before
       T60, and the tests at T60 would not be run.)

       A crucial aspect to the design and function of wdmd is that if any sin‐
       gle  source  does  not pass tests for the fire timeout, the watchdog is
       guaranteed to fire, regardless of whether other sources on  the  system
       have passed or failed.  A spurious reset due to the combined effects of
       multiple failing tests as shown above, is an accepted side effect.

       The wdmd init script will load the softdog module if no other  watchdog
       module has been loaded.

       wdmd  cannot be used on the system with any other program that needs to
       open /dev/watchdog, e.g. watchdog(8).

   Test Source: clients
       Using libwdmd, programs connect to wdmd via a  unix  socket,  and  send
       regular messages to wdmd to update an expiry time for their connection.
       Every test interval, wdmd will check if the expiry time for  a  connec‐
       tion has been reached.  If so, the test for that client fails.

   Test Source: scripts
       wdmd  will run scripts from a designated directory every test interval.
       If a script exits with 0, the test is considered a success, otherwise a
       failure.  If a script does not exit by the end of the test interval, it
       is considered a failure.

OPTIONS
       --version, -V
                Print version.

       --help, -h
                Print usage.

       --dump, -d
                Print debug information from the daemon.

       --probe, -p
                Print path of functional watchdog device.  Exit code  0  indi‐
                cates a functional  device  was  found.  Exit code 1 indicates
                a functional device was not found.

       -D
                Enable debugging to stderr and don't fork.

       -H 0|1
                Enable (1) or disable (0) high priority features such as real‐
                time scheduling priority and mlockall.

       -G name
                Group ownership for the socket.

       -S 0|1
                Enable (1) or disable (0) script tests.

       -s path
                Path to scripts dir.

       -k num
                Kill unfinished scripts after num seconds.

       -w path
                The path to the watchdog device to try first.

                                  2011-08-01                           WDMD(8)
```


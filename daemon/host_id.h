#ifndef __HOST_ID_H__
#define __HOST_ID__H__

int host_id_leader_read(uint64_t host_id, struct leader_record *leader_ret);
int start_host_id(void);
void stop_host_id(void);
int our_host_id_renewed(void);
int print_hostid_state(char *str);

#endif

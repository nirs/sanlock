#ifndef __HOST_ID_H__
#define __HOST_ID__H__

int start_host_id(void);
void stop_host_id(void);
int our_host_id_renewed(void);
int host_id_alive(uint64_t host_id);

#endif

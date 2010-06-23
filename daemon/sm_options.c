#include <time.h>

#include "sm.h"
#include "sm_options.h"

struct sm_options options = {"", 1};
time_t oldest_renewal_time;
struct sm_timeouts to;

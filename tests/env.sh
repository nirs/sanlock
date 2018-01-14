# Setup the environment for testing sanlock.

# Use built libraries from source
export LD_LIBRARY_PATH=$PWD/wdmd:$PWD/src

# Disable privileged operations, allowing to run sanlock daemon as
# non-privileged user.
export SANLOCK_PRIVILEGED=0

# Use temporary sanlock run dir, usable for non-privileged user.  This
# is used by sanlock daemon to create a lockfile and socket, and by
# sanlock clients for communicating with the daemon.
export SANLOCK_RUN_DIR=/tmp/sanlock

# Import sanlock extension module from source.
export PYTHONPATH=$PWD/python

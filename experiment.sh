#!/bin/bash

#set -e

# https://stackoverflow.com/a/2173421
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

function die() {
    echo "$1" 1>&2
    exit 1
}

function hexpad16() {
    printf '%016X' "$1"
}


if (( $# != 1 )) ; then
    die "ERROR: wrong num args"
fi

echo "build_start_time $(date '+%s')"
gretel_enable=$1
echo gretel_enable=$gretel_enable

if (($gretel_enable)) ; then
    echo cd nginx_yesgretel
    cd nginx_yesgretel
else
    echo cd nginx_nogretel
    cd nginx_nogretel
fi


# NOTE: ask for password here to make sure we can sudo in bg.
sudo echo got sudo

if (($gretel_enable)) ; then
    sudo rm -f gretel_bcc.log

    export TIMEFORMAT='bcc %e %U %S'
    time sudo python3 ../gretel_bcc.py &
    bcc_pid=$!
    echo "bcc_pid=$bcc_pid"
fi

user_typ="5"
placeholder="0x1234" # TODO timestamp?
prefix="$(hexpad16 $user_typ)$(hexpad16 $placeholder)$(hexpad16 $placeholder)"

sudo docker-compose pull # ignore errors
sudo docker-compose build || die "ERROR in docker-compose build"

mkdir -p nginx_{a,b}.logs/
sudo rm -f nginx_{a,b}.logs/*.log

function get_container_ids() {
  # sets $container_ids
  readarray -t container_ids < <(docker ps --no-trunc | grep gretel | sed -e 's/^\([^ ]*\)[[:space:]].*/\1/')
}

sudo docker-compose down # just in case
get_container_ids
if (( ${#container_ids[@]} != 0 )) ; then
  die "ERROR: gretel containers are already running"
fi

sudo docker-compose up --build -d --wait || die "ERROR in docker-compose up"
get_container_ids

if (( ${#container_ids[@]} != 2 )) ; then
  die "ERROR: failed to start containers"
fi

function stat_docker() {
    for container_id in ${container_ids[@]}; do
        echo cat /sys/fs/cgroup/system.slice/docker-${container_id}.scope/cpu.stat
        cat /sys/fs/cgroup/system.slice/docker-${container_id}.scope/cpu.stat

        echo cat /sys/fs/cgroup/system.slice/docker-${container_id}.scope/memory.stat
        cat /sys/fs/cgroup/system.slice/docker-${container_id}.scope/memory.stat

    done
}

if (($gretel_enable)) ; then
  while [ ! -f gretel_bcc.log ]; do
      echo "INFO: waiting for bcc to start and create gretel_bcc.log..."
  done
fi

#tshark

echo "experiment_start_time $(date '+%s')"

stat_docker
i=0
while (( $i < 10000 )) ; do
    export TIMEFORMAT="curl i=$i %R %U %S"
    #time curl --no-progress-meter -H "gretel: ${prefix}$(hexpad16 $i)" localhost/api  -iv -o curl_session_${i}.txt
    time curl --no-progress-meter -H "gretel: ${prefix}$(hexpad16 $i)" localhost/api -o /dev/null
    i=$(($i+1))
done
stat_docker
ls -l nginx_{a,b}.logs/

if (($gretel_enable)) ; then
    ls -l gretel_bcc.log
    # https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
    echo cat "/proc/$bcc_pid/stat"  
    cat "/proc/$bcc_pid/stat"
fi

echo "experiment_end_time $(date '+%s')"


if (($gretel_enable)) ; then
    export TIMEFORMAT='bcc2 %e %U %S' # TODO necessary?
    kill -SIGINT "$bcc_pid"
fi

sudo docker-compose down || echo "WARN: error in docker-compose down"

echo "build_end_time $(date '+%s')"

# TODO tshark!!

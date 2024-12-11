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

gretel_enable=$1

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
    rm -f gretel_bcc.log
    sudo python3 ../gretel_bcc.py &
    bcc_pid=$!

fi

user_typ="5"
placeholder="0x1234" # TODO timestamp?
prefix="$(hexpad16 $user_typ)$(hexpad16 $placeholder)$(hexpad16 $placeholder)"

sudo docker-compose pull # ignore errors
sudo docker-compose build || die "ERROR in docker-compose build"

mkdir -p nginx{1,2}.logs/
rm -f nginx{1,2}.logs/*.log

sudo docker-compose up --build -d --wait || die "ERROR in docker-compose up"

readarray -t containers < <(docker ps --no-trunc | grep gretel | sed -e 's/^\([^ ]*\)[[:space:]].*/\1/')

function stat_docker() {
    for container_id in ${containers[@]}; do
        echo cat /sys/fs/cgroup/system.slice/docker/docker-${container_id}.scope/cpu.stat
        cat /sys/fs/cgroup/system.slice/docker/docker-${container_id}.scope/cpu.stat

        echo cat /sys/fs/cgroup/system.slice/docker/docker-${container_id}.scope/memory.stat
        cat /sys/fs/cgroup/system.slice/docker/docker-${container_id}.scope/memory.stat

    done
}


stat_docker
i=0
while (( $i < 10000 )) ; do
    time curl -H "gretel: ${prefix}$(hexpad16 $i)" localhost/api  -o /dev/null
    echo $i
    i=$(($i+1))
done
stat_docker

if (($gretel_enable)) ; then
    # https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
    echo cat "/proc/$bcc_pid/stat"
    cat "/proc/$bcc_pid/stat"
    kill -SIGINT "$bcc_pid"
fi

sudo docker-compose down || echo "WARN: error in docker-compose down"

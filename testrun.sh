#!/bin/bash

function hexpad16() {
    printf '%016X' "$1"
}

user_typ="5"
placeholder="0x1234" # TODO timestamp?
prefix="$(hexpad16 $user_typ)$(hexpad16 $placeholder)$(hexpad16 $placeholder)"

#curl -vi -H "gretel: ${prefix}$(hexpad16 0x11111111)" localhost
curl -vi -H "gretel: ${prefix}$(hexpad16 0x22222222)" localhost/api
#curl -H "gretel: ${prefix}$(hexpad16 0x33333333)" localhost/api
#curl -H "gretel: ${prefix}$(hexpad16 0x44444444)" localhost
#curl -H "gretel: ${prefix}$(hexpad16 0x55555555)" localhost/api

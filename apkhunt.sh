#!/bin/sh

DIR="apks"

if [ ! -d $DIR ]; then
    mkdir $DIR
fi

docker run -v $(pwd)/$DIR:/app/apks --rm apkhunt/apkhunt "$@"
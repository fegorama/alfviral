#!/bin/sh

export COMPOSE_FILE_PATH="${PWD}/docker/docker-compose.yml"

start() {
    docker volume create openssh-keys-volume
    docker-compose -f "$COMPOSE_FILE_PATH" up --build -d
}

down() {
    if [ -f "$COMPOSE_FILE_PATH" ]; then
        docker-compose -f "$COMPOSE_FILE_PATH" down
    fi
}

purge() {
    docker volume rm -f openssh-keys-volume
}

tail() {
    docker-compose -f "$COMPOSE_FILE_PATH" logs -f
}

tail_all() {
    docker-compose -f "$COMPOSE_FILE_PATH" logs --tail="all"
}

case "$1" in
  start)
    start
    tail
    ;;
  stop)
    down
    ;;
  purge)
    down
    purge
    ;;
  tail)
    tail
    ;;
  *)
    echo "Usage: $0 {start|stop|purge|tail}"
esac
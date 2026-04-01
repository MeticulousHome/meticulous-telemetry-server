#!/usr/bin/env bash
set -euo pipefail

TELEMETRY_SERVER_DIR="$(dirname "$(realpath "$0")")"
SERVICE_NAME="meticulous-telemetry-server.service"

print_header() {
  local message=$1
  echo ""
  echo " > $message"
  echo ""
}

print_message() {
  local message=$1
  local symbol="->"
  if [ $# -ge 2 ]; then
    symbol=$2
  fi

  echo "   $symbol $message"
}

use_sudo(){
  if [ "$EUID" == "0" ]; then
    "$@"
  else
    sudo "$@"
  fi
}


install_service() {

  SYSTEMD_SERVICE_DIR="/etc/systemd/system"

  print_header "Setting up $SERVICE_NAME"

  use_sudo systemctl daemon-reexec
  use_sudo systemctl daemon-reload

  set +e
  use_sudo systemctl status "$SERVICE_NAME" >/dev/null 2>&1
  RESULT=$?
  set -e
  # if the unit is not found systemctl returns 4
  if [ $RESULT -eq 4 ]; then
    print_message "Installing service…"
    use_sudo cp -u "$TELEMETRY_SERVER_DIR/$SERVICE_NAME" "$SYSTEMD_SERVICE_DIR"

    use_sudo systemctl daemon-reexec
    use_sudo systemctl daemon-reload
  fi

  set +e
  use_sudo systemctl status "$SERVICE_NAME" >/dev/null 2>&1
  RESULT=$?
  set -e
  if [ $RESULT -lt 4 ]; then
    print_message "$SERVICE_NAME successfully installed"
    print_message "setting \$TELEMETRY_SERVER_PATH environment variable to '$TELEMETRY_SERVER_DIR'"

    if [ ! -d "/opt/telemetry-service/" ]; then
      use_sudo mkdir -p "/opt/telemetry-service/"
    fi

    echo "TELEMETRY_SERVER_PATH=$TELEMETRY_SERVER_DIR" >"/opt/telemetry-service/env"

    print_message " TELEMETRY_SERVER_PATH variable successfully saved as $TELEMETRY_SERVER_DIR"

    use_sudo systemctl enable "$SERVICE_NAME"

    print_message "$SERVICE_NAME is enabled, will start on every boot"
    print_message "You can start the service now using"
    print_message "systemctl start $SERVICE_NAME" " >>> "
  else
    print_message "failed to install $SERVICE_NAME" "[x]"
    print_message "You can still run the service manually executing"
    print_message "docker compose -f $TELEMETRY_SERVER_DIR/docker-compose.yml --wait" " >>> "
  fi

}

show_help() {
    cat <<EOF
Usage: ${0##*/} [OPTIONS]
Install the telemetry server as service or just rebuild the docker image

By default the service file is created, the service enabled and run

Available options:
    --only-build              Only rebuild the docker compose image
    --not-start               Skip starting the service (skipped when --only-build)

EOF
}

build_docker_image() {
  print_header "building docker image"
  use_sudo docker compose build --no-cache
}

INSTALL_SERVICE=1;
START_SERVICE=1;

#Parse command line arguments
for arg in "$@"; do
    case $arg in
    --only-build) INSTALL_SERVICE=0; START_SERVICE=0 ;;
    --not-start) START_SERVICE=0 ;;
    --help)
        show_help
        exit 0
        ;;
    *)
        echo "Invalid option: $arg"
        show_help
        exit 1
        ;;
    esac
done

build_docker_image

if [[ INSTALL_SERVICE -eq 1 ]]; then
  install_service
fi

if [[ START_SERVICE -eq 1 ]]; then
  print_header "starting $SERVICE_NAME"
  use_sudo systemctl start $SERVICE_NAME
fi

print_header "DONE"
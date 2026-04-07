#!/usr/bin/env bash
set -euo pipefail

TELEMETRY_SERVER_DIR="$(dirname "$(realpath "$0")")"
SERVICE_NAME="meticulous-telemetry-server.service"
SYSTEMD_SERVICE_DIR="/etc/systemd/system"
SERVICE_ENV_FILE="/opt/telemetry-service/env"


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

show_sudo(){
  if [ "$EUID" == "0" ]; then
    echo ""
  else
    echo "sudo "
  fi
}

install_service() {
  print_header "Setting up $SERVICE_NAME"

  print_message "Installing service…"
  write_service
  use_sudo systemctl daemon-reexec
  use_sudo systemctl daemon-reload

  set +e
  use_sudo systemctl status "$SERVICE_NAME" >/dev/null 2>&1
  RESULT=$?
  # if the unit is not found systemctl returns 4
  if [ $RESULT -lt 4 ]; then
    print_message "$SERVICE_NAME successfully installed"
    print_message "setting \$TELEMETRY_SERVER_PATH environment variable to '$TELEMETRY_SERVER_DIR'"

    if [ ! -d "$(dirname $SERVICE_ENV_FILE)" ]; then
      if ! use_sudo mkdir -p "$(dirname $SERVICE_ENV_FILE)"; then
        uninstall_service
        print_message "Failed to create the required environment file and directory for the service, service cleaned"
        exit 2;
      fi
    fi
    set -e
    printf "%s\n" "TELEMETRY_SERVER_PATH=\"$TELEMETRY_SERVER_DIR\"" | use_sudo tee "$SERVICE_ENV_FILE" >/dev/null

    print_message " TELEMETRY_SERVER_PATH variable successfully saved as $TELEMETRY_SERVER_DIR"
  else
    print_message "failed to install $SERVICE_NAME" "[x]"
    print_message "You can still run the service manually executing"
    print_message "$(show_sudo)docker compose -f \"$TELEMETRY_SERVER_DIR/docker-compose.yml\" up --wait"
    exit 3
  fi
  set -e
}

uninstall_service() {

  print_header "Removing $SERVICE_NAME"

  if [[ -f "$SYSTEMD_SERVICE_DIR/$SERVICE_NAME" ]]; then
    use_sudo rm "$SYSTEMD_SERVICE_DIR/$SERVICE_NAME"
    print_message "$SERVICE_NAME file removed"
    use_sudo systemctl daemon-reexec
    use_sudo systemctl daemon-reload
  fi

  if [[ -d "$(dirname "$SERVICE_ENV_FILE")" ]]; then 
    use_sudo rm -rf "$(dirname "$SERVICE_ENV_FILE")"
    print_message "$SERVICE_NAME env file removed"
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

write_service(){
  cat <<EOF | use_sudo tee "$SYSTEMD_SERVICE_DIR/$SERVICE_NAME" >/dev/null
[Unit]
Description=Meticulous Telemetry Server instance
After=nginx.service docker.service

#make sure \$TELEMETRY_SERVER_PATH is defined (should be done in install.sh)
[Service]
EnvironmentFile=$SERVICE_ENV_FILE
ExecStartPre=/bin/bash -c '[[ -n "\$TELEMETRY_SERVER_PATH" ]] || { echo "TELEMETRY_SERVER_PATH not found"; exit 10; }'
ExecStart=docker compose -f "\${TELEMETRY_SERVER_PATH}/docker-compose.yml" up
ExecStop=docker compose -f "\${TELEMETRY_SERVER_PATH}/docker-compose.yml" down
Restart=always
RestartSec=10
RestartPreventExitStatus=10
StandardOutput=null

[Install]
WantedBy=multi-user.target

EOF
}

build_docker_image() {
  print_header "building docker image"
  use_sudo docker compose -f "$TELEMETRY_SERVER_DIR/docker-compose.yml" build --no-cache
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

EXIT_CODE=0
if [[ INSTALL_SERVICE -eq 1 ]]; then

  install_service
  
  if use_sudo systemctl enable "$SERVICE_NAME"; then
    print_message "$SERVICE_NAME is enabled, will start on every boot"
  else
    print_message "failed to enable $SERVICE_NAME, it will not start on boot"
  fi
  print_message "You can start the service now using"
  print_message "$(show_sudo)systemctl start $SERVICE_NAME"

  if [[ START_SERVICE -eq 1 ]]; then
  
    print_header "starting $SERVICE_NAME"
  
    if use_sudo systemctl start $SERVICE_NAME; then
      print_header "DONE"
      exit 0
    fi
  
    print_message "Could not start the service"
    EXIT_CODE=4;
  fi

  print_header "You can manually start the service running"
  print_message "$(show_sudo)systemctl start meticulous-telemetry-server.service"

else
  print_header "You can manually start the service running"
  print_message "$(show_sudo)docker compose -f \"$TELEMETRY_SERVER_DIR/docker-compose.yml\" up --wait"
fi

exit $EXIT_CODE
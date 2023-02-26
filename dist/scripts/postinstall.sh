#!/bin/sh -e

cleanInstall() {
	printf "\033[32m Reload the service unit from disk\033[0m\n"
	systemctl daemon-reload ||:

	printf "\033[32m Set the enabled flag for the service unit\033[0m\n"
	systemctl enable edgebit-agent.service ||:

    printf "\033[32m *************************************************\033[0m\n"
    printf "\033[32m Edit /etc/edgebit/config.yaml, then\033[0m\n"
    printf "\033[32m systemctl start edgebit-agent.service\033[0m\n"
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"

	printf "\033[32m Reload the service unit from disk\033[0m\n"
	systemctl daemon-reload ||:

	systemctl restart edgebit-agent.service ||:
}

# Step 2, check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    # $1 == version being installed
    cleanInstall
    ;;
esac

"""Command-line entry point for the sequential firewall rule analyzer."""

from netaddr.contrib.firewall_analyzer import main


if __name__ == '__main__':
    raise SystemExit(main())

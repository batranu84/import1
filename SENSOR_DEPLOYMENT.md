# ShadowStrike Distributed Sensor Runtime

A controller cannot discover a private customer LAN that is not routed to it. ShadowSensor solves that by running the discovery worker inside the authorized customer network and initiating outbound authenticated requests to the ShadowStrike controller.

## Controller

For a sensor on the same Mac, the default `127.0.0.1` controller is valid. For another host/site, start the controller on an approved private/VPN address:

```bash
./start-remote-controller.command
```

Do not expose the controller directly to the public Internet. Use an approved routed private path or VPN and a host firewall.

## Sensor host

Copy the same ShadowStrike release folder to the authorized sensor host and install the maintained native discovery backends once:

```bash
./install-discovery-tools.command
```

Register the sensor in the controller UI. The token is shown once.

Normal worker:

```bash
./sensor.command --controller http://CONTROLLER:8765 --assessment-id ID --agent-id ID --token TOKEN --site SITE --port-profile adaptive --interval 60
```

Deep privileged worker, recommended when the engagement permits raw OS/L2 fingerprinting:

```bash
./sensor.command --privileged --controller http://CONTROLLER:8765 --assessment-id ID --agent-id ID --token TOKEN --site SITE --port-profile adaptive --interval 60
```

The privileged wrapper prepares the Python environment before elevation, then runs only the sensor worker through `sudo`. This enables arp-scan and Nmap raw TCP/IP OS fingerprinting while the controller remains unprivileged.

The worker sends a heartbeat, reports local/routed private networks, retrieves the controller-approved CIDRs, scans only those CIDRs, and uploads normalized evidence. Transient controller/network failures are retried rather than terminating the worker.

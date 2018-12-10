def launch():

    from reactive_fwd import launch
    launch()

    from pox.openflow.discovery import launch
    launch(eat_early_packets=True)

    from pox.openflow.keepalive import launch
    launch(interval=15)  # 15 seconds

    from pox.samples.pretty_log import launch
    launch()

    from pox.log.level import launch
    launch(DEBUG=True)
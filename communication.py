from slackclient import SlackClient
from flask import current_app as app

def sendSlack(channel, token, message, debug):
    """simple Slack sender for status reports"""
    #
    # simple input validation
    #
    if debug:
        app.logger.debug("Not sending out SLACK message: " + str(message))
        return 0

    if channel is None or token is None or message is None:
        return

    sc = SlackClient(token)

    sc.api_call(
        "chat.postMessage",
        channel=channel,
        text=message
    )
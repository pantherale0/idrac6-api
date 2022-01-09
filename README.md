# Dell IDRAC6 - API Client

Forked from https://gitlab.com/kaangoksal/idrac6-api

This is a API client writted in python, to connect to idrac6 using its "not so restful" API.

Essentially this client replicates the same queries as your web browser does to the data manager in IDRAC.

Hopefully in the future i'll be able to wrap this into a fully fledged client for IDRAC6 to work as an alternative to the current dated (and slow) UI.

Next steps is to emulate the java applets and wrap that into a HTML5 client directly (rather than simply run Java over a VNC connection served to the user has a web page in HTML5) the idea of this is to create a version that supports all of the iDRAC 6 yummys from the java app, natively on any platform via a web browser.

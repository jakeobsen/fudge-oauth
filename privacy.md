---
title: Privacy policy
---

# Privacy policy for Fudge's relay

This policy covers the fudge-oauth relay at https://fudge-oauth.rackofpain.net/, which jakeobsen runs for Fudge.
It doesn't cover any other fudge-oauth relay, such as one you run yourself.

Last updated: 2026-11-22.

## What the relay does

Fudge signs in to services such as GitHub and Atlassian through the relay, because a service's client secret can't ship inside an app.
During a sign-in, your browser passes through the relay on its way to the service and on its way back.
Fudge then sends the relay the one-time code from the service, and the relay exchanges it with the service and passes your tokens back to Fudge.
Refreshing a token works the same way.

## What the relay keeps

Nothing but its log (below).
It has no database, no cookies and no sessions.
Codes and tokens pass through it only while it answers the request.
What a sign-in needs between its steps travels encrypted inside the sign-in itself, and expires within 10 minutes.

## What the relay logs

One line per request: the path without its query, the service, the status, the time and how long it took.
When a service refuses a request or can't be reached, one more line with the service and the status it answered.
When it starts, it logs its own settings: its address and the services it offers.
It never logs a code, a token, a header or what a request contains.
Its web server, or a proxy in front of it, may note the IP address a connection comes from, for example when a secure connection fails before a request is made.

## The services you sign in to

The service you sign in to handles your account under its own privacy policy.
The relay asks it only for the access the extension asks for.

## Questions

Open an issue at https://github.com/jakeobsen/fudge-oauth/issues.

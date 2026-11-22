---
title: Privacy policy
---

# Privacy policy for Fudge's relay

This policy covers the fudge-oauth relay that Fudge uses, at https://fudge-oauth.rackofpain.net/.
It doesn't cover any other fudge-oauth relay, such as one you run yourself.

Last updated: 2026-11-22.

## What the relay does

The relay lets Fudge sign you in to third-party services, such as GitHub and Atlassian, without the app holding those services' secrets.
It takes part in the sign-in and in refreshing your access, and passes the result back to Fudge.

## What we collect

We don't create accounts, use cookies or keep a database.
Sign-in codes and access tokens pass through the relay only while a request is being handled.
They are never stored, and our logs are set up to leave them out.

Like most online services, the relay and the infrastructure in front of it keep technical logs to run the service, keep it secure and fix problems.
These may include your IP address, the time of a request, the page requested (without its parameters), browser details and whether the request succeeded.

## Service providers

The relay runs behind Cloudflare and our own web servers, which handle connections to it.
Cloudflare processes connection data under its own privacy policy.

## Third-party services

The service you sign in to handles your account under its own privacy policy.
The relay only requests the access Fudge asks for.

## How long we keep data

Logs are kept only as long as needed to run and secure the service, and are then deleted.

## Your rights

You can ask what data we hold about you and ask us to delete it.

## Questions

Open an issue on [GitHub](https://github.com/jakeobsen/fudge-oauth/issues).

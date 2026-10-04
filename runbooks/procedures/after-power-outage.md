# After a power outage

What to do when the identity server and workstations come back after losing power. Written from a lab test on
2026-10-04: three hard power cuts (both machines, plug pulled) and one where a workstation came back five minutes
before the server. **Every time, everything came back by itself.** The risk after an outage is not a hidden fault; it
is "fixing" something that would have cleared in a minute.

## Steps

1. **Start the identity server first** (srv1: the identity service, the certificate authority and the DNS server
   all run there). In the test it answered about 15 seconds after power-on.
2. **Wait about a minute, then run a check** on the server. A clean check (no findings) means it is ready.
3. **Then start the workstations,** and check one. In the test, workstations were clean about 5 seconds after they
   answered.

## Normal in the first minute or two (do not repair)

- **TIME_UNVERIFIED** on a machine that just started: its clock has not been confirmed yet. It cleared in about
  40 seconds in the test.
- **KANIDM_UNREACHABLE and UNIXD_OFFLINE** on a workstation that started before the server: it cannot reach the
  server yet. **People who have logged in to that workstation before can still log in** (from its saved copy of
  their account). It cleared by itself within a minute of the server coming back; nothing needed refreshing.
- Any finding on a machine that started less than 3 minutes ago says so in its evidence ("this host started 40 s
  ago…", or "the identity server started…"). Check again before repairing.

## Not normal (act on it)

- **TLS_CERT_EXPIRED** after a long outage: if the server was off longer than its certificate's renewal window, the
  certificate can expire while it is off. The decision form offers the existing repair (a new certificate from the
  project's certificate authority).
- **SERVICE_DOWN still there after 3 minutes:** read the service's log first, as its runbook says.
- **Anything else still there after 3 minutes:** follow its decision form as usual.

## What the outage takes away

- **A person who has never logged in to a workstation cannot log in to it until the server is back.** Only people
  the workstation already knows are saved there.
- Account changes (new people, removed access) reach workstations only once the server is back.

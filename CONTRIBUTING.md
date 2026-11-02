# Contributing to YANP Nas

YANP Nas is licensed under **GPL-2.0-only**. Contributions must be compatible
with that license. Keep changes small and explain the user-visible behavior,
native Linux operations involved, tests run, and known limits.

Use Debian 13 native packages. Do not add containers, alternate backend stacks,
arbitrary shell execution, or a Node.js server dependency. Web operations must
remain in PHP; privileged actions belong in the allowlisted Python agent.

Never commit NAS configuration, credentials, setup tokens, session files, dumps
or logs. The installer must never format disks or overwrite unrelated firewall
tables. Verify authorization and validation on the agent as well as PHP.

Run the checks in the README. Hardware tests belong on a dedicated test server
with disposable data, and must be reported separately from isolated tests.

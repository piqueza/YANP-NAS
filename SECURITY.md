# Security reporting

Do not include credentials, tokens, private file contents, database dumps or
unredacted NAS logs in public issues. When a GitHub repository is published,
use its private vulnerability reporting feature if enabled. If no private
channel is listed, ask the maintainer for one before posting exploit details.

The Python management agent runs as root and the authenticated PHP application
is a trusted administrative component. Review `docs/ARCHITECTURE.md` before
changing that boundary. Authentication, path validation, Samba configuration,
firewall rollback and installer permission changes need relevant regression tests.

Version 0.2.0 is a first test release. Automated checks do not replace target
hardware acceptance or an independent security review.

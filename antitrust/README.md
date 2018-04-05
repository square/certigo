# Antitrust

Antitrust is a library for trusting trust stores.

It contains "known bad" trust stores, like Superfish, Turktrust and Wosign.
You can use this to notice if your trust stores contain any bad CAs.  It also
has well-known trust stores so you can notice if your trust stores contain any
old, custom, or unusual CAs.

The API is pretty simple:
 - You give it a CA and antitrust tells you about it.
 - You give it a leaf and intermediates, and antitrust tells you what each known
   trust store would trust it.

TODO:
  It would be nice to also catalog "common" intermediate certs, to provide more
helpful diagnosis of chain issues.  AIA fetching could help here, too.

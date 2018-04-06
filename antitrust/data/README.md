# Certificate Authority data

This package consists of data used by antitrust.  The data must be updated
manually, as it's inconvenient to require remote services during builds. Some
of the generation steps require being run on various operating systems too.

The data.go file is generated from the .json files in each of the
subdirectories.  See the README.md in those for instructions.
Run go generate 

## Antitrust

The root programs below describe good certificates, some of which have been
untrusted over time.  However, there are some known bad certificates which
never appeared in any root store.

Those are curated here, in the antitrust root program.  Any root, intermediate,
or leaf certificate which has been leaked, abused, mis-issued, or known to be
malicious is eligible to be included here.

Notable examples include leaked roots like Superfish and edellroot plus CAs
which have been removed for bad behaviour, like Wosign and TURKTRUST.

## Trusted Data structure

Each root program is modelled as a map of SHA256 fingerprints to a small struct
that describes the state of the root in the program.  Notably it has the dates
and release name it was added, removed, and other constraints on the roots.
Release names are things like "kitkat" or "rhel6".

There is a map of fingerprints to x509.Certificates.  This is common to all the
root programs 

## Trusted Data Sources

Mozilla is one of the major root programs, used by many Linux distros
in addition to Firefox.  See the mozilla/README.md but also the debian and
redhat ones.  We might want to include other Linux distros in the future.
Android and ChromeOS I suspect follows the Mozilla program.

Apple runs a root program for iOS and macOS.

Microsoft runs a root program for their products.

Oracle runs one for Java.

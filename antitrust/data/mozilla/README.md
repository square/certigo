# Mozilla CA Certificate Store

The Mozilla trust store is commonly used in Linux distros in addition to its
origin in Firefox.  

Information about this store can be found at:
https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/

We fetch the original data from here:
https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

TODO: This is source-controlled, so we could historical data when we add support for that.
That way we can pull the exact Firefox release numbers CAs changed in.
# Want-Digest header support for Nginx

This Perl module enables support for the Want-Digest header in Nginx.  When a
client request includes this header, Nginx will generate a checksum using the
specified algorithm (md5, sha, sha-256, and sha-512 are supported).


### Status

Warning: this is a naive, proof-of-concept code sample, that is not ready for
production use.  It probably has serious security and/or performance bugs.


### Setup

```bash
apt-get install nginx nginx-extras
mkdir /usr/share/nginx/perl
cp WantDigest.pm /usr/share/nginx/perl
```

See `nginx.conf` for basic configuration, and `demo.sh` for sample curl
commands to demonstrate the header functionality.


### Vagrant

There is a Vagrant configuration in `Vagrantfile`.  You can spin up a VM with
the module installed with:

```bash
vagrant up
```


### Acknowledgements

Based on sample code by Matt Martz <matt@sivel.net>:
* https://gist.github.com/sivel/1870822 and
* https://blog.rackspace.com/add-the-content-md5-http-header-to-nginx

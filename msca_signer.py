#!/usr/bin/env python
"""
Create a private key for and have it signed by Microsoft Certificate Server
"""

try:
    import requests
    import socket
    import re
    import sys
    import argparse
    from OpenSSL import crypto, SSL
    import tarfile
    import time
    import os
except KeyboardInterrupt:
    pass

socket.setdefaulttimeout(20)
server = "ca.local.net"
outputfolder = "~/certs/"
C = 'ChangeMe'
ST = 'ChangeMe'
L = 'ChangeMe'
O = 'ChangeMe'
OU = 'ChangeMe'

###########
# LETS GO #
###########


def gencert(request):
    """
    Push the csr to the microsoft certificate server for signing
    """
    url = '[http://'+server+'/certsrv/certrqxt.asp]http://'+server+'/certsrv/certrqxt.asp'
    url2 = '[http://'+server+'/certsrv/certfnsh.asp]http://'+server+'/certsrv/certfnsh.asp'
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, request)
    payload = {'Mode': 'newreq', 'CertRequest': csr.replace('\n', ''), 'CertAttrib': 'CertificateTemplate:UnixAuthentication', 'SaveCert': 'yes', 'TargetStoreFlags': '0', 'Thumbprint': '', 'FriendlyType': 'Saved-Request Certificate (3/8/2016 10:03:40 AM)'}
    reqnumber = 0

    s = requests.Session()
    r = s.get(url, timeout=30)
    if __debug__:
        print r.status_code
        print r.headers
        print r.request.headers

    r = s.post(url2, data=payload, timeout=30)

    if __debug__:
        print r.status_code
        print r.headers
        print r.request.headers
        print r.text
    for item in r.text.split("\n"):
        if "certnew.cer?ReqID=" in item:
            line = item.strip()
            pat = r'.*ReqID=(.\d{1,5})\&amp.*'
            reqnumber = re.findall(pat, line).pop()
            break
        elif "Your certificate request was denied." in item:
            print "Request was denied, check request"
            exit()
    return reqnumber


def generatefiles(mkfile, request):
    """
    Write key and csr from memory to file on disk
    """
    if ".csr" in mkfile:
        f = open(outputfolder+mkfile, "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
        f.close()
    elif ".key" in mkfile:
        f = open(outputfolder+mkfile, "w")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        f.close()
    else:
        print "Failed to write: "+mkfile
        exit()


def gencsr(name, sans=None):
    """
    Generate a csr
    """
    print "Creating csr"

    # Default values in my case
    csrfile = name+'.csr'
    keyfile = name+'.key'
    type_rsa = crypto.TYPE_RSA

    # Build class
    req = crypto.X509Req()
    # needed for IIS
    req.set_version(0)
    req.get_subject().CN = name
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L
    req.get_subject().organizationName = O
    req.get_subject().organizationalUnitName = OU
    # Appends SAN to have 'DNS:'
    ss = []
    if sans:
        for i in sans:
            ss.append("DNS: %s" % i)
            ss = ", ".join(ss)
    # Add in extensions
    base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    x509_extensions = base_constraints
    # If there are SAN entries, append the base_constraints to include them.
    if ss:
        san_constraint = crypto.X509Extension("subjectAltName", False, ss)
        x509_extensions.append(san_constraint)
        req.add_extensions(x509_extensions)

    # Gen Keys
    key = crypto.PKey()
    key.generate_key(type_rsa, 2048)
    req.set_pubkey(key)
    req.sign(key, "sha256")
    if __debug__:
        print crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    generatefiles(csrfile, req)
    generatefiles(keyfile, key)
    return req


def getcert(reqnumber, hostname):
    """
    Download signed cert from microsoft ca server.
    """
    print "downloading cert from "+server
    url = "[http://"+server+"/certsrv/certnew.cer?ReqID="+reqnumber+"&Enc=b64]http://"+server+"/certsrv/certnew.cer?ReqID="+reqnumber+"&Enc=b64"
    r = requests.get(url, stream=True)
    if __debug__:
        print url
        print r.text
    crtfile = open(outputfolder+hostname+'.crt', 'w')
    crtfile.write(r.text)
    crtfile.flush()
    crtfile.close()
    tar = tarfile.open(outputfolder+hostname+".tar", "w")
    for name in [outputfolder+hostname+".key", outputfolder+hostname+".csr", outputfolder+hostname+".crt"]:
        tar.add(name, arcname=name.split('/')[-1])
    tar.close()
    if __debug__:
        t = tarfile.open(outputfolder+hostname+".tar", 'r')
        for member_info in t.getmembers():
            print member_info.name
    for name in [outputfolder+hostname+".key", outputfolder+hostname+".csr", outputfolder+hostname+".crt"]:
        os.remove(name)


def main():
    """
    main program
    """

    # parse cmdline args
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname', nargs='?')
    args = parser.parse_args()

    if args.hostname:
        print 'lets go...'
        request = gencsr(args.hostname)
        req = gencert(request)
        getcert(req, args.hostname)
    elif not sys.stdin.isatty():
        print 'enter FQDN hostname'
        print sys.stdin.read()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
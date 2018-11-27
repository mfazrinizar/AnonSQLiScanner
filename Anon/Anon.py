#!/usr/bin/env python

# 27/11/2018
# Anon6372098
# https://github.com/Anon6372098/
# D4RK SYST3M F41LUR3 S33K3R
# Apache 2.0
# Laporkan bug ke email saya di opsi --tentang

from ext.useragents import getUserAgent
from ext.geturls import GetUrls
from ext.checksqli import checkSqli
from ext.filewriter import writeAsText
import os
import sys
import urllib2
from urlparse import urlparse
import time


vuln_urls = []

def showBanner():
    """ Show Banner Message """
    print """Anon SQL Injection Scanner by Anon6372098
Email       : anon6372098.id@gmail.com
Github      : https://github.com/Anon6372098/
Team        : D4RK SYST3M F41LUR3 S33K3R (DSFS)
Homepage    : https://www.dsfs-indo.zone.id/
Pembaruan   : (27/11/2018)"""


def showHelp():
    """ show commands and help message """
    print """-d untuk scan dengan memberi google dork
-f <tempat/jalur file beserta namanya> untuk scan website dari file yang dituju
--tentang untuk melihat informasi seputar saya """


def interruptHandler():
    os.system('clear')
    print "User mengganggu prosesnya"
    option = raw_input("Apakah anda ingin menyimpan hasil scan ? [y/n] ")
    if option == 'y':
        # Opening the file and Saving the process.
        vulnerabilities = list(set(vuln_urls))
        iowriter = open("vulnerables.txt", 'w')

        for item in vulnerabilities:
            iowriter.write(item + "\n")
        iowriter.close()  # Closing the file
        print "Selesai"
    else:
        print "Hasil scan tidak akan di simpan"
    exit()


class SqliScan:
    """ Main class of this script
        Includes:
          - website status checker
          - sql vulnerability scanner
          - io writer to save vulnerabilities """

    def __init__(self, urls):
        self.urlRequest(self.urlReader(urls))
        self.saveVulnerabilities()

    def urlReader(self, urls):
        """ read the url and removing newlines """
        splittedUrls = urls.split('\n')
        if '' in splittedUrls:  # Removing empty line
            splittedUrls.pop(splittedUrls.index(''))
        return splittedUrls

    def urlRequest(self, urls):
        """ check for website status, and if online scan for vulnerability """
        for site in urls:
            parsed = urlparse(site)
            url = parsed.scheme + "://" + parsed.netloc

            os.system('clear')
            print " Informasi Website"
            print " Nama Domain  : " + parsed.netloc
            print " Protokol     : " + parsed.scheme
            print " Tempat/Jalur : " + parsed.path
            print " Query[s]     : " + parsed.query + "\n"

            # These will check user URL whether it missed some necessary input.
            if len(parsed.scheme) == 0:
                print "Protokol tidak ditemukan"
                time.sleep(1); continue
            elif len(parsed.path) == 0:
                print "Tempat/Jalur tidak ditemukan"
                time.sleep(1); continue
            elif len(parsed.query) == 0:
                print "Query tidak ditemukan"
                time.sleep(1); continue
            else:
                if self.siteStatus(url):  # True mean website is online
                    self.scanVulnerability(site)

    def siteStatus(self, url):
        """ check website online or offline status """
        header = {'User-Agent': getUserAgent()}
        request = urllib2.Request(url, None, header)

        print "Mengecek apakah website berstatus online atau offline"
        try:
            urllib2.urlopen(request)
            print "Terhubung, URL valid :)"
            return True

        except urllib2.HTTPError, error:
            print error.code
            time.sleep(1)
            return False

        except urllib2.URLError, error:
            print error.reason
            time.sleep(1)
            return False

    def scanVulnerability(self, url):
        """ Scan the url by giving semi-colon on different id param """
        trigger_1 = "'"
        parsedUrl = urlparse(url)

        try:
            parms = dict([item.split("=") for item in parsedUrl[4].split("&")])
            parm_keys = parms.keys()

            if len(parms) == 1:
                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + trigger_1
                print "Testing: " + vuln_test
                self.verifyVulnerability(vuln_test)

            elif len(parms) == 2:
                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + trigger_1 + "&" + parm_keys[1] + "=" + parms[parm_keys[1]]
                print "Testing: " + vuln_test
                self.verifyVulnerability(vuln_test)

                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + "&" + parm_keys[1] + "=" + parms[parm_keys[1]] + trigger_1
                print "Testing: " + vuln_test
                self.verifyVulnerability(vuln_test)

            elif len(parms) == 3:
                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + trigger_1 + "&" + parm_keys[1] + "=" + parms[parm_keys[1]] + "&" + parm_keys[2] + "=" + parms[parm_keys[2]]
                print "Testing:" + vuln_test
                self.verifyVulnerability(vuln_test)

                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + "&" + parm_keys[1] + "=" + parms[parm_keys[1]] + trigger_1 + "&" + parm_keys[2] + "=" + parms[parm_keys[2]]
                print "Testing: " + vuln_test
                self.verifyVulnerability(vuln_test)

                vuln_test = parsedUrl.scheme + "://" + parsedUrl.netloc + parsedUrl.path + "?" + parm_keys[0] + "=" + parms[parm_keys[0]] + "&" + parm_keys[1] + "=" + parms[parm_keys[1]] + "&" + parm_keys[2] + "=" + parms[parm_keys[2]] + trigger_1
                print "Testing: " + vuln_test
                self.verifyVulnerability(vuln_test)

        except ValueError:
            print "Query Tidak Ditemukan"
        except IndexError:
            print "Query Juga Tidak Ditemukan"
    
    def verifyVulnerability(self, url):
        """ verify website vulnerability and add to vulnerabilities list if found """
        global vuln_urls
        try:
            header = {'User-Agent': getUserAgent()}
            request = urllib2.Request(url, None, header)
            http_request = urllib2.urlopen(request)
            html = http_request.read()
            scannedResult = checkSqli(html)  # return dictionary

            for resp in scannedResult.itervalues():
                try:
                    resp.group()
                    print "SQL Injection error ditemukan :)"
                    time.sleep(1)
                    vuln_urls.append(url)
                except:
                    pass

        except urllib2.HTTPError, error:
            print 'Gagal dengan error kode - %s.' % error.code
    
    def saveVulnerabilities(self):
        """ save the vulnerabilities to text file """
        urls = list(set(vuln_urls))
        os.system('clear')
        if len(urls) != 0:
            writeAsText('anon_vuln_sqli.txt', urls)
        else:
            print "Tidak Ada URL Yang Vuln Ditemukan"
        print "Proses selesai"


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == '-d':
        urls = GetUrls().dorkScanner()

    elif len(sys.argv) == 2 and sys.argv[1] == '--tentang':
        showBanner()
        exit()

    elif len(sys.argv) == 2 and sys.argv[1] == '-petunjuk':
        showHelp()
        exit()

    elif len(sys.argv) == 3 and sys.argv[1] == '-f':
        urls = GetUrls().fileReader(sys.argv[2])

    else:
        print "invalid option"
        exit()

    try:
        SqliScan(urls)
    except KeyboardInterrupt:
        interruptHandler()

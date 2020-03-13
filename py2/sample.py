# -*- coding: utf-8 -*-

import vulns

def report(id):
    r = vulns.report(id)
    if len(r)<1:
        print "id %s is not correct"%id
        return
    print "ID =", r['ID']
    print "Title =", r['Title']
    print "Overview =", r['Overview']
    print "Impact =", r['Impact']
    print "CPEs =", ''.join(r['CPEs'])
    print "CVEs =", ''.join(r['CVEs'])
    print "CVSSv3 =", ''.join(r['CVSSv3'])

def digest(id):
    r = vulns.digest(id)
    if len(r)<1:
        print "id %s is not correct"%id
        return
    print "ID =", r['ID']
    print "Vulns =", ','.join(r['Vulns'])
    print "Impacts =", ','.join(r['Impacts'])
    print "CPEs =", ','.join(r['CPEs'])
    print "CVEs =", ','.join(r['CVEs'])
    print "CVSSv3 =", ','.join(r['CVSSv3'])
    print "Scores =", ','.join(r['Scores'])

def disp(id):
    print "---------------------------------------"
    report(id)
    print "---------------------------------------"
    digest(id)

def main():
    vulns.init("/opt/vulns/config.json")
    #print vulns.report("JVNDB-2018-000001")
    disp("JVNDB-2018-000001")
    disp("JVNDB-2018-000002")
    disp("JVNDB-2018-001002")
    disp("JVNDB-2018-999999")

if __name__ == "__main__":
    main()

#!/usr/bin/env python

import base64
from collections import namedtuple
from ConfigParser import RawConfigParser, NoOptionError
from ctypes import Structure, CDLL, byref, cast, string_at, c_uint, c_void_p, c_uint, c_ubyte, c_char_p
import logging
from optparse import OptionParser
import os
try:
    from sqlite3 import dbapi2 as sqlite
except ImportError:
    from pysqlite2 import dbapi2 as sqlite
from subprocess import Popen, CalledProcessError, PIPE
import sys


LOGLEVEL_DEFAULT = 'warn'

log = logging.getLogger()
PWDECRYPT = 'pwdecrypt'

SITEFIELDS = ['id', 'hostname', 'httpRealm', 'formSubmitURL', 'usernameField', 'passwordField', 'encryptedUsername', 'encryptedPassword', 'guid', 'encType', 'plain_username', 'plain_password' ]
Site = namedtuple('FirefoxSite', SITEFIELDS)
'''The format of the SQLite database is:
(id                 INTEGER PRIMARY KEY,hostname           TEXT NOT NULL,httpRealm          TEXT,formSubmitURL      TEXT,usernameField      TEXT NOT NULL,passwordField      TEXT NOT NULL,encryptedUsername  TEXT NOT NULL,encryptedPassword  TEXT NOT NULL,guid               TEXT,encType            INTEGER);
'''



#### These are libnss definitions ####
class SECItem(Structure):
	_fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]
	
class secuPWData(Structure):
	_fields_ = [('source',c_ubyte),('data',c_char_p)]

(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0, 1, 2, 3)

#### End of libnss definitions ####


def get_default_firefox_profile_directory():
    profiles_dir = os.path.expanduser('~/.mozilla/firefox')
    profile_path = None

    cp = RawConfigParser()
    cp.read(os.path.join(profiles_dir, "profiles.ini"))
    for section in cp.sections():
        if not cp.has_option(section, "Path"):
            continue

        if (not profile_path or
            (cp.has_option(section, "Default") and cp.get(section, "Default").strip() == "1")):
            profile_path = os.path.join(profiles_dir, cp.get(section, "Path").strip())

    if not profile_path:
        raise RuntimeError("Cannot find default Firefox profile")

    return profile_path
    
def get_encrypted_sites(firefox_profile_dir=None):
    if firefox_profile_dir is None:
        firefox_profile_dir = get_default_firefox_profile_directory()
    password_sqlite = os.path.join(firefox_profile_dir, "signons.sqlite")
    query = '''SELECT id, hostname, httpRealm, formSubmitURL,
                      usernameField, passwordField, encryptedUsername,
                      encryptedPassword, guid, encType, 'noplainuser', 'noplainpasswd' FROM moz_logins;'''

    connection = sqlite.connect(password_sqlite)
    try:
        cursor = connection.cursor()
        cursor.execute(query)

        for site in map(Site._make, cursor.fetchall()):
          yield site
    finally:
        connection.close()

def decrypt(encrypted_string, firefox_profile_directory, password = None):
    log = logging.getLogger('firefoxpasswd.decrypt')
    execute = [PWDECRYPT, '-d', firefox_profile_directory]
    if password:
        execute.extend(['-p', password])
    process = Popen(execute,
                    stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = process.communicate(encrypted_string)
    
    log.debug('Sent: %s', encrypted_string)
    log.debug('Got: %s', output)
    
    NEEDLE = 'Decrypted: "' # This string is prepended to the decrypted password if found
    output = output.strip()
    if output == encrypted_string:
        log.error('Password was not correct. Please try again without a '
                   'password or with the correct one')
    
    index = output.index(NEEDLE) + len(NEEDLE)
    password = output[index:-1] # And we strip the final quotation mark
    return password


class NativeDecryptor(object):
    def __init__(self, directory, password = None):
        self.directory = directory
        self.log = logging.getLogger()
        
        self.libnss = CDLL('libnss3.so')
        if self.libnss.NSS_Init(directory) != 0:
            self.log.error('Could not initialize NSS')
    
    
        self.password = password
        
        if password is None:
            pwdata = secuPWData()
            pwdata.source = PW_NONE
            pwdata.data = 0
        else: # It's not clear whether this actually works
            pwdata = secuPWData()
            pwdata.source = PW_PLAINTEXT
            pwdata.data = password # It doesn't actually work :-(
            # Unfortunately, http://fossies.org/dox/firefox-3.6.16.source/secutil_8c_source.html#l00405
            slot = self.libnss.PK11_GetInternalKeySlot();
            if slot:
                print "Needs init %r %s" % (slot, type(slot))
                print self.libnss.PK11_NeedUserInit(slot)
            self.libnss.PK11_ChangePW(slot, pwdata.data, 0);
        
        self.pwdata = pwdata
    
    def __del__(self):
        self.libnss.NSS_Shutdown()
    
    def decrypt(self, string, *args):
        libnss =  self.libnss

        uname = SECItem()
        dectext = SECItem()        
        pwdata = self.pwdata
        
        cstring = SECItem()
        cstring.data  = cast (c_char_p (base64.b64decode (string)), c_void_p)
        cstring.len = len (base64.b64decode (string))
        if libnss.PK11SDR_Decrypt (byref (cstring), byref (dectext), byref (pwdata)) == -1:
	        raise Exception (libnss.PORT_GetError ())
	        
        decrypted_data = string_at (dectext.data, dectext.len)
	
    	return decrypted_data
	
	
    def encrypted_sites(self):
        sites = get_encrypted_sites(self.directory)

        return sites

    def decrypted_sites(self):
        sites = self.encrypted_sites()
        
        for site in sites:
            plain_user = self.decrypt(site.encryptedUsername)
            plain_password = self.decrypt(site.encryptedPassword)
            site = site._replace(plain_username=plain_user, plain_password=plain_password)
            
            yield site

def get_firefox_sites_with_decrypted_passwords(firefox_profile_directory = None, password = None):
    if not firefox_profile_directory:
        firefox_profile_directory = get_default_firefox_profile_directory()
    #decrypt = NativeDecryptor(firefox_profile_directory).decrypt
    for site in get_encrypted_sites(firefox_profile_directory):
        plain_user = decrypt(site.encryptedUsername, firefox_profile_directory, password)
        plain_password = decrypt(site.encryptedPassword, firefox_profile_directory, password)
        site = site._replace(plain_username=plain_user, plain_password=plain_password)
        log.debug("Dealing with Site: %r", site)
        log.info("user: %s, passwd: %s", plain_user, plain_password)
        yield site

def main_decryptor(firefox_profile_directory, password):
    if not firefox_profile_directory:
        firefox_profile_directory = get_default_firefox_profile_directory()

    decryptor = NativeDecryptor(firefox_profile_directory, password)
    
    for site in decryptor.decrypted_sites():
        print site
    
if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-d", "--directory", default=None,
                  help="the Firefox profile directory to use")
    parser.add_option("-p", "--password", default=None,
                  help="the master password for the Firefox profile")
    parser.add_option("-l", "--loglevel", default=LOGLEVEL_DEFAULT,
                  help="the level of logging detail [debug, info, warn, critical, error]")
    parser.add_option("-n", "--native", default=True, action='store_true',
                  help="use the native decryptor, i.e. make Python use "
                  "libnss directly instead of invoking the helper program"
                  "DEFUNCT! this option will not be checked.")
    parser.add_option("-e", "--external", default=False, action='store_true',
                  help="use an external program `pwdecrypt' to actually "
                    "decrypt the passwords. This calls out a lot and is dead "
                    "slow. "
                    "You need to use this method if you have a password "
                    "protected database though.")
    options, args = parser.parse_args()
    
    loglevel = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'critical':logging.CRITICAL,
                'error': logging.ERROR}.get(options.loglevel, LOGLEVEL_DEFAULT)
    logging.basicConfig(level=loglevel)
    log = logging.getLogger()
    
    if not options.external:
        sys.exit (main_decryptor(options.directory, options.password))
    else:
        for site in get_firefox_sites_with_decrypted_passwords(options.directory, options.password):
            print site

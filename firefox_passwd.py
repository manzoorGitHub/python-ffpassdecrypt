#!/usr/bin/env python

from collections import namedtuple
from ConfigParser import RawConfigParser, NoOptionError
import logging
from optparse import OptionParser
import os
try:
    from sqlite3 import dbapi2 as sqlite
except ImportError:
    from pysqlite2 import dbapi2 as sqlite
from subprocess import Popen, CalledProcessError, PIPE



LOGLEVEL_DEFAULT = 'warn'

#log = logging.getLogger()
PWDECRYPT = 'pwdecrypt'

SITEFIELDS = ['id', 'hostname', 'httpRealm', 'formSubmitURL', 'usernameField', 'passwordField', 'encryptedUsername', 'encryptedPassword', 'guid', 'encType', 'plain_username', 'plain_password' ]
Site = namedtuple('FirefoxSite', SITEFIELDS)
'''The format of the SQLite database is:
(id                 INTEGER PRIMARY KEY,hostname           TEXT NOT NULL,httpRealm          TEXT,formSubmitURL      TEXT,usernameField      TEXT NOT NULL,passwordField      TEXT NOT NULL,encryptedUsername  TEXT NOT NULL,encryptedPassword  TEXT NOT NULL,guid               TEXT,encType            INTEGER);
'''


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
    execute = [PWDECRYPT, '-d', firefox_profile_directory]
    if password:
        execute.extend(['-p', password])
    process = Popen(execute,
                    stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = process.communicate(encrypted_string)
    
    NEEDLE = 'Decrypted: "' # This string is prepended to the decrypted password if found
    output = output.strip()
    index = output.index(NEEDLE) + len(NEEDLE)
    password = output[index:-1] # And we strip the final quotation mark
    return password

def get_firefox_sites_with_decrypted_passwords(firefox_profile_directory = None, password = None):
    if not firefox_profile_directory:
        firefox_profile_directory = get_default_firefox_profile_directory()
    for site in get_encrypted_sites(firefox_profile_directory):
        plain_user = decrypt(site.encryptedUsername, firefox_profile_directory, password)
        plain_password = decrypt(site.encryptedPassword, firefox_profile_directory, password)
        site = site._replace(plain_username=plain_user, plain_password=plain_password)
        log.debug("Dealing with Site: %r", site)
        log.info("user: %s, passwd: %s", plain_user, plain_password)
        yield site

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-d", "--directory", default=None,
                  help="the Firefox profile directory to use")
    parser.add_option("-p", "--password", default=None,
                  help="the master password for the Firefox profile")
    parser.add_option("-l", "--loglevel", default=LOGLEVEL_DEFAULT,
                  help="the level of logging detail [debug, info, warn, critical, error]")
    options, args = parser.parse_args()
    
    loglevel = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'critical':logging.CRITICAL,
                'error': logging.ERROR}.get(options.loglevel, LOGLEVEL_DEFAULT)
    logging.basicConfig(level=loglevel)
    log = logging.getLogger()

    for site in get_firefox_sites_with_decrypted_passwords(options.directory, options.password):
        print site

# This is a script that can be used in conjunction with offlineimap.
#
# Your remote repository in .offlineimaprc should look similar to this:
#
# [Repository Remote]
# type = IMAP
# remotehost = imap.gmail.com
# remoteuser = user@gmail.com
# remotepasseval = get_password("imap.gmail.com", "user@gmail.com")
# ssl = yes
#
# And don't forget to set 'pythonfile' in the 'general' section.

import authinfo

def get_password(host, user):
    entry = authinfo.query(host=host, user=user)

    if entry is None:
        return None

    return entry.password

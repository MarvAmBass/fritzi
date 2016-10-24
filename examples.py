#!/usr/bin/python

from fritzi import Fritzi

hostname = raw_input("FritzBox Hostname: ")
username = raw_input("Username (Press Enter if you don't have one): ")
password = raw_input("Password: ")

fritzi = Fritzi(hostname)
fritzi.login(username, password)

print("Session ID: " + fritzi.sid)
print("Is Session ID valid? " + str(fritzi.isSessionIdStillValid(fritzi.sid)))
print("")

# getting overview
overview = fritzi.getOverview()

# getting wifi and guestwifi settings
wifiSettings = fritzi.getWifiSettings()
guestWifiSettings = fritzi.getGuestWifiSettings()

# enable first wifi (2,4GHz or 5GHz whatever comes first) (won't do anything if this is already enabled)
wifiSettings[wifiSettings.keys()[0]]['active'] = True
wifiSettings = fritzi.changeWifi(wifiSettings)

# enable guest wifi (won't do anything if this is already enabled)
guestWifiSettings['active'] = True
guestWifiSettings = fritzi.changeGuestWifi(guestWifiSettings)

# log out
fritzi.logout()

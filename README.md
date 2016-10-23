# fritzi
___Fritzi is a small Python Library (pure, single file, standard library only) to control FRITZ!Box Routers___

_It's tested to work with FRITZ!OS: 06.51_

I've tried to get as much informations possible about the API by watching network traffic via chrome.

You can login via _Password only_ or _Username + Password_.

It works best if the things you want to do are already configured - but some things could also be initially configured using this library.

Change Wifi Status, guest Wifi Status obtain infos etc. etc.

## How does it work:

- Create a Object with the hostname/ip of the Fritz!Box (obj = Fritzi('fritz.box'))
- call obj.login(username, password) (If you don't have a username just use "")
 - you'll obtain a Session ID (obj.sid) to authenticate all following requests (till obj.logout)
- obtain informations about the current settings e.g. obj.getOverview()
- call obj.logout() to logout the session.

## Features:

### Infos:

- complete Overview as Python Object (includes everything you need)

_simple_
- get external IP Address
- get installed FritzOS Version Number
- get List of connected clients

_extended_
- get wifi settings
- get guest wifi settings

### Settings:

- changeWifi
- changeGuestWifi

those are pretty simple to use. If you give them _None_ as settings argument, the service will be disabled
if you obtain a guest/wifi settings object with the methods mentioned above, and give it to them as settings argument
nothing should change since it's whats already configured.

But you can change everything of the session object, which will alter your wifi and guest wifi settings.
This way you can enable/disable them and much more - just play around.

_to enable guest wifi you first must enable or have an active wifi_

### Checks:

- is Session ID (obj.sid) is still valid or if you need to login again


## needed background infos:

### Security Modes for Guest Wifi

- 1 = WEP (I'm not sure)
- 2 = WPA (TKIP)
- 3 = WPA2 (CCMP)
- 4 = WPA + WPA2
- 5 = open

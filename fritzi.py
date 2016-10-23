#!/usr/bin/python

import httplib
import urllib
import ssl
import re
import codecs
import hashlib
import json

class Fritzi:

  INVALID_SESSION_ID = "0000000000000000"



  def __init__(self, hostname):
    self.connection = httplib.HTTPSConnection(hostname, timeout=5, context=ssl._create_unverified_context())
    self.sid = Fritzi.INVALID_SESSION_ID



  def __extractor(self, extractor, data):
    extractor = re.search(extractor, data)
    if extractor:
      return extractor.group(1)
    else:
      raise ValueError("couldn't find data to extract in data")



  def __extractChallenge(self, data):
    return self.__extractor("<Challenge>(.*?)</Challenge>", data)



  def __extractSid(self, data):
    return self.__extractor("<SID>(.*?)</SID>", data)



  def __getHeaders(self):
    return {"Content-type": "application/x-www-form-urlencoded", "Accept": "*/*"}



  def login(self, username, password):
    if username is None:
      username = ""

    self.connection.request("GET", "/login_sid.lua")
    firstResponse = self.connection.getresponse()
    dataWithChallengeAndSID = firstResponse.read()

    challenge = self.__extractChallenge(dataWithChallengeAndSID);
    sid = self.__extractSid(dataWithChallengeAndSID);

    md5Hasher = hashlib.md5()
    md5Hasher.update(codecs.encode(challenge + "-" + password, "utf-16-le"))

    challengeResponse = challenge + "-" + md5Hasher.hexdigest()

    loginurl = "/login_sid.lua?username=" + username + "&response=" + challengeResponse

    self.connection.request("GET", loginurl)
    secondResponse = self.connection.getresponse()
    dataWithFinalSID = secondResponse.read()
    self.sid = self.__extractSid(dataWithFinalSID);



  def logout(self):
    params = urllib.urlencode({'xhr': 1, 'sid': self.sid, 'no_sidrenew': '', 'logout': 1})
    self.connection.request("POST", "/index.lua", params, self.__getHeaders())
    self.connection.getresponse().read()
    self.sid = None



  def isSessionIdStillValid(self, sessionId):
    self.connection.request("GET", "/login_sid.lua?0=0&sid="+sessionId)
    response = self.connection.getresponse()
    responseData = response.read()
    extractedSid = self.__extractSid(responseData);
    return (sessionId == extractedSid)



  def getOverview(self):
    params = urllib.urlencode({'xhr': 1, 'sid': self.sid, 'no_sidrenew': '', 'lang':'de', 'page': 'overview', 'type': 'all'})
    self.connection.request("POST", "/data.lua", params, self.__getHeaders())
    response = self.connection.getresponse()
    return json.loads(response.read())



  # overview extractors

  def getExternalIPv4(self, overview):
    return overview['data']['ipv4']['txt'][1].split(' ')[1]

  def getFritzOSVersion(self, overview):
    return float(overview['data']['fritzos']['nspver'])

  def getConnectedDevices(self, overview):
    return overview['data']['net']['devices']

  def getWifiSettings(self, overview):
    wlan24 = overview['data']['wlan24']['txt']
    wlan5 = overview['data']['wlan5']['txt']
    return {"wifi24": {"ssid": wlan24.split('GHz: ')[1], "active": (wlan24.split(',')[0] != "aus")}, "wifi5": {"ssid": wlan5.split('GHz: ')[1], "active": (wlan5.split(',')[0] != "aus") }}



  # special extractors
  def getGuestWifiSettings(self):
    overview = self.getOverview()
    wifiSettings = self.getWifiSettings(overview)
    wifiActive = False
    for wifikey in wifiSettings:
      wifi = wifiSettings[wifikey]
      if wifi['active']:
        wifiActive = True

    if not wifiActive:
      # temporarly enable wifi to check guest wifi settings
      wifiSettings[wifiSettings.keys()[0]]['active'] = True
      self.changeWifi(wifiSettings)

    params = urllib.urlencode({'xhr': 1, 'sid': self.sid, 'no_sidrenew': '', 'lang':'de', 'page': 'wGuest'})
    self.connection.request("POST", "/data.lua", params, self.__getHeaders())
    response = self.connection.getresponse().read()

    if not wifiActive:
      # back to old settings - disable wifi
      wifiSettings[wifiSettings.keys()[0]]['active'] = False
      self.changeWifi(wifiSettings)

    guestWifiActive = False
    guestWifiSsid = None
    guestWifiKey = None
    guestWifiSecMode = None

    guestWifiPushLogins = False

    guestWifiLimited = False

    guestWifiUntrusted = False

    guestWifiUserIsolation = False

    guestWifiMaxUptimeActive = False
    guestWifiMaxUptimeMinutes = None
    guestWifiMaxUptimeForce = False

    for line in response.split('\n'):

      if 'id="uiViewActivateGuestAccess"' in line:
        guestWifiActive = ("checked" in line)
      elif 'id="uiPushService"' in line:
        guestWifiPushLogins = ("checked" in line)
      elif 'id="uiGroupAccess"' in line:
        guestWifiLimited = ("checked" in line)
      elif 'id="uiUntrusted"' in line:
        guestWifiUntrusted = ("checked" in line)
      elif 'id="uiUserIsolation"' in line:
        guestWifiUserIsolation = ("checked" in line)
      elif 'id="uiViewDownTimeActiv"' in line:
        guestWifiMaxUptimeActive = ("checked" in line)
      elif 'id="uiViewDisconnectGuestAccess"' in line:
        guestWifiMaxUptimeForce = ("checked" in line)
      elif 'id="uiViewGuestSsid"' in line:
        guestWifiSsid = self.__extractor('value=\"(.*?)\"', line)
      elif 'id="uiViewWpaKey"' in line:
        guestWifiKey = self.__extractor('value=\"(.*?)\"', line)
      elif "option value=" in line:
        if "selected" in line:
          value = int(self.__extractor('value=\"(.*?)\"', line))
          if value < 10:
            guestWifiSecMode = value
          else:
            guestWifiMaxUptimeMinutes = value


    return {"active": guestWifiActive, "ssid": guestWifiSsid, "key": guestWifiKey, "secMode": guestWifiSecMode, "pushLogins": guestWifiPushLogins, "limited": guestWifiLimited, "untrusted": guestWifiUntrusted, "userIsolation": guestWifiUserIsolation, "maxUptimeActive": guestWifiMaxUptimeActive, "maxUptimeMinutes": guestWifiMaxUptimeMinutes, "maxUptimeForce": guestWifiMaxUptimeForce}



  # fritzbox settings changers
  def changeWifi(self, wifiSettings):
    wifiParams = {'xhr': 1, 'sid': self.sid, 'print': '', 'validate':'apply', 'active': 'on'}
    dataParams = {'xhr': 1, 'sid': self.sid, 'no_sidrenew': '', 'lang':'de', 'apply': '', 'print': '', 'oldpage': '/wlan/wlan_settings.lua', 'active': 'on'}

    if wifiSettings is not None:
      for wifikey in wifiSettings:
        wifi = wifiSettings[wifikey]
        if wifi['active']:
          wifiGhz = wifikey.split("wifi")[1]
          try:
            del wifiParams['active']
            del dataParams['active']
          except:
            pass

          additionalParams = {'SSID': wifi['ssid'], 'active_'+wifiGhz: 'on', 'SSID_'+wifiGhz: wifi['ssid'], 'hidden_ssid': 'on'}

          wifiParams.update(additionalParams)
          dataParams.update(additionalParams)

    self.connection.request("POST", "/wlan/wlan_settings.lua?sid="+self.sid, urllib.urlencode(wifiParams), self.__getHeaders())
    self.connection.getresponse().read()

    self.connection.request("POST", "/data.lua", urllib.urlencode(dataParams), self.__getHeaders())
    self.connection.getresponse().read()

    return self.getWifiSettings(self.getOverview())



  def changeGuestWifi(self, guestWifiSettings):
    # autoupdate=on &activate_guest_access=on &guest_ssid=GuestSSID &sec_mode=3 &wpa_key=SecretKey!
    # autoupdate=on &activate_guest_access=on &guest_ssid=GuestSSID &sec_mode=3 &wpa_key=SecretKey!
    # SecMode
    # 1 = WEP (I'm not sure), 2 = WPA (TKIP), 3 = WPA2 (CCMP), 4 = WPA + WPA2, 5 = open
    # push service [push_service=on]
    # mailing and surfing only [group_access=on]
    # accept usage contract [untrusted=on]
    # user isolation [user_isolation=on]
    # wifi for specific time: down_time_activ=on down_time_value=1260 (<- Minutes)
    #   optional extra - disconnect only if no guest is connected: disconnect_guest_access=on
    wifiParams = {'xhr': 1, 'sid': self.sid, 'print': '', 'validate':'apply', 'autoupdate': 'on'}
    dataParams = {'xhr': 1, 'sid': self.sid, 'no_sidrenew': '', 'lang':'de', 'apply': '', 'print': '', 'oldpage': '/wlan/guest_access.lua', 'autoupdate': 'on'}

    if guestWifiSettings is not None:
      if guestWifiSettings['active']:
        print("activate guest-wifi:")
        additionalParams = {'activate_guest_access': 'on', 'guest_ssid': guestWifiSettings['ssid'], 'sec_mode': guestWifiSettings['secMode'], 'wpa_key': guestWifiSettings['key']}
        wifiParams.update(additionalParams)
        dataParams.update(additionalParams)

        if guestWifiSettings['pushLogins']:
          optionalParams = {'push_service': 'on'}
          wifiParams.update(optionalParams)
          dataParams.update(optionalParams)

        if guestWifiSettings['limited']:
          optionalParams = {'group_access': 'on'}
          wifiParams.update(optionalParams)
          dataParams.update(optionalParams)

        if guestWifiSettings['untrusted']:
          optionalParams = {'untrusted': 'on'}
          wifiParams.update(optionalParams)
          dataParams.update(optionalParams)

        if guestWifiSettings['userIsolation']:
          optionalParams = {'user_isolation': 'on'}
          wifiParams.update(optionalParams)
          dataParams.update(optionalParams)

        if guestWifiSettings['maxUptimeActive']:
          optionalParams = {'down_time_activ': 'on', 'down_time_value': maxUptimeMinutes}
          wifiParams.update(optionalParams)
          dataParams.update(optionalParams)
          if guestWifiSettings['maxUptimeForce']:
            optionalParams = {'disconnect_guest_access': 'on'}
            wifiParams.update(optionalParams)
            dataParams.update(optionalParams)

    self.connection.request("POST", "/wlan/guest_access.lua?sid="+self.sid, urllib.urlencode(wifiParams), self.__getHeaders())
    self.connection.getresponse().read()

    self.connection.request("POST", "/data.lua", urllib.urlencode(dataParams), self.__getHeaders())
    self.connection.getresponse().read()

    return self.getGuestWifiSettings()



if __name__ == '__main__':
  import sys
  if len(sys.argv) != 2:
    print("to use this programm add fritzbox hostname/ip as argument:")
    print("./" + sys.argv[0]+ " fritz.box")
    sys.exit(1)

  hostname = sys.argv[1]

  print("Hostname: "+hostname)
  print("")

  username = raw_input("Username (Press Enter if you don't have one): ")
  password = raw_input("Password: ")

  print("")

  fritzi = Fritzi(hostname)
  fritzi.login(username, password)

  print("Session ID: " + fritzi.sid)
  print("Is Session ID valid? " + str(fritzi.isSessionIdStillValid(fritzi.sid)))
  print("")

  overview = fritzi.getOverview()

  print("External IPv4 Address: " + fritzi.getExternalIPv4(overview))
  print("")
  print("Fritz!OS Version: " + str(fritzi.getFritzOSVersion(overview)))
  print("")
  print("Connected Clients:")
  print(str(fritzi.getConnectedDevices(overview)))
  print("")

  wifiSettings = fritzi.getWifiSettings(overview)
  guestWifiSettings = fritzi.getGuestWifiSettings()

  print("")
  print("Wifi Settings:")
  print(wifiSettings)
  print("")

  print("")
  print("Guest Wifi Settings:")
  print(guestWifiSettings)
  print("")

  print("")
  print("Overview JSON Dump:")
  print("")
  print(json.dumps(overview, sort_keys=True, indent=4, separators=(',', ': ')))

  print("")
  print("")
  print("Logout")
  fritzi.logout()
  print("done")

# A2S Anti Spam #

A2S Anti Spam is a plugin which automatically IP bans an A2S Query attacker thus preventing your server from crashing.

# What games are supported? #
It has only been tested in CSGO and I believe that is the only game which is supported as of now, because we rely on the [PTAH](https://forums.alliedmods.net/showthread.php?p=2464171) extension (Thanks, komashchenko)

### Installation is easy, Just download the latest version from [here](https://bitbucket.org/SM91337/a2s-spam-ban/downloads) and copy to your server in the correct same structure.###

### WhiteList file ###
In the sourcemod/configs folder you will see a2s-whitelist.txt, here you can add IPs or Hostnames which won't get banned.
This can be useful for people who use HLSW for example.
If you have a Dynamic IP, then I would suggest getting something like [NO-IP](http://www.noip.com/) and then you can add your hostname to the whitelist instead of updating it each time your IP changes.

### Cvars ###
As of now, there is only one cvar, this allows you to specify how long an attacker gets banned for. By default, it's 5 mins.
* sm_a2s_bantime

### Requirements ###
* [SMRcon](https://forums.alliedmods.net/showthread.php?t=168403)
* [PTAH](https://forums.alliedmods.net/showthread.php?t=289289)

### Donate ###
If you like my work and want to help support me, Then you are more than welcome to [donate](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VS79974BRC244), although you don't have to but I would love you <3!
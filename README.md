## droidwalker
droidwalker is a poorly written bash script to search decompiled .apk files for secrets such as access tokens and API keys.

Unlike most tools that search for keywords like "password" and "config", droidwalker uses regex to find and identify hardcoded secrets and outputs the discovered keys directly in the terminal. Althrough the script was originally created for Android applications, it can be used to search any directory for leaked secrets.

To use droidwalker, simply run droidwalker.sh and specify the target directory containing the decompiled .apk file(s) as a command-line argument.

__Sample output__:
```
droidwalker v1.0

[*] MailChimp API Key(s) found:
d30e8218c88b1ce8414709280361b5f2-us1

Description: MailChimp API Key. Can be used to access the affected MailChimp account.


[*] Branch SDK Key(s) found:
key_live_bglZn2p4MskqhjauKrknLmopyEkpp8FS

Description: Branch SDK Key. While not considered secret, it can be used to create deeplinks to arbitrary URLs on the associated domain if not restricted. Depending on the context, this could be considered a security issue.


[*] Cloudinary API Key/Secret Pair(s) found:
cloudinary://462121443479271:1qQoDVsPR1A-WOAYwsUKQ4D0luk

Description: Cloudinary URL containing API Key and Secret. Can be used as HTTP Basic Auth credentials to access the affected account.


[*] Mapbox Secret Access Token(s) found:
sk.eyJ1Ijoid2Fpa2UiKCJhIjoiY2s5MWZ5dHItMGFjNjNnbzlyc2dxcXBiNCJ9.gj1dqBFbVePZgo-acwWBvw

Description: Mapbox Secret Access Token. Can be used to access the affected Mapbox account.


[*] New Relic License Key(s) found:
5929cc141ac623a8805b92665552dcbbbd7eNRAL

Description: New Relic License Key. Can be used to send fake metric data to the affected account. According to New Relic documentation, it should be treated like a password.


[i] Scan completed.
```

Please note that the script can take some time to complete if the target directory contains several decompiled apps.

### Credits
Most of the used regex expressions are takens from other repos. Here are the sources used:
- [gitleaks](https://github.com/zricethezav/gitleaks)
- TomNomNom's [gf](https://github.com/tomnomnom/gf)
- [truffleHog](https://github.com/dxa4481/truffleHog)

### Contributing
I gladly accept suggestions for improvements and additions to the script/regexs/descriptions. Feel free to raise an issue.


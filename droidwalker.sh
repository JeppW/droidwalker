#!/usr/bin/env bash

set -e

printf "droidwalker v1.0\n\n"

# database - regexs and information
# hacky solution to the lack of support for better suited data structures in bash
names=(
	'Google API Key'
	'Google OAuth Secret'
	'Google ReCAPTCHA Key'
	'GCP Key'
	'AWS Access Key ID'
	'AWS Secret Key'
	'Amazon MWS Auth Token'
	'Facebook Access Token'
	'Facebook Secret Key'
	'Twitter Secret Key'
	'Mailgun API Key'
	'MailChimp API Key'
	'Twilio API Key'
	'PayPal Braintree Access Token'
	'Square Access Token'
	'Square OAuth Secret'
	'Stripe Standard API Key'
	'Stripe Restricted API Key'
	'Picatic API Key'
	'Github Access Token'
	'Branch SDK Key'
	'Branch Secret Key'
	'Cloudinary API Key/Secret Pair'
	'Mapbox Secret Access Token'
	'Slack API Token'
	'Slack Webhook'
	'Accengage Partner ID and Private Key'
	'New Relic License Key'
	'LinkedIn Client ID'
	'LinkedIn Secret Key'
	'Heroku API Key'
	'Microsoft Azure Tenant Client Secret'
	'HTTP Basic Auth Credentials'
)

regexs=(
	'AIza[0\-9A\-Za\-z\-_\-]{35}'
	'ya29\.[0\-9A\-Za\-z\-_]+'
	'^6[0\-9a\-zA\-Z_\-]{39}$'
	"(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0\-9a\-z\\\-_]{35}]['\"]"
	'AKIA[0\-9A\-Z]{16}'
	"(?i)aws(.{0,20})?(?\-i)['\"][0\-9a\-zA\-Z/+]{40}['\"]"
	'amzn\.mws\.[0\-9a\-f]{8}\-[0\-9a\-f]{4}\-[0\-9a\-f]{4}\-[0\-9a\-f]{4}\-[0\-9a\-f]{12}'
	'EAACEdEose0cBA[0\-9A\-Za\-z]+'
	"(?i)(facebook|fb)(.{0,20})?(?\-i)['\"][0\-9a\-f]{32}"
	"(?i)twitter(.{0,20})?['\"][0\-9a\-z]{35\,44}"
	'key\-[0\-9a\-zA\-Z]{32}'
	'[0\-9a\-f]{32}\-us[0\-9]{1,2}'
	'SK[0-9a-fA-F]{32}'
	'access_token\$production\$[0\-9a\-z]{16}\$[0\-9a\-f]{32}'
	'sqOatp\-[0\-9A\-Za\-z\-_\-]{22}'
	'sq0csp\-[0\-9A\-Za\-z\-_\-]{43}'
	'sk_live_[0\-9a\-zA\-Z]{24}'
	'rk_live_[0\-9a\-zA\-Z]{24}'
	'sk_live_[0\-9a\-z]{32}'
	'[a\-zA\-Z0\-9_\-]*:[a\-zA\-Z0\-9_\-]+@github\.com*'
	'key_live_[0\-9A\-Za\-z\-_\-]{32}'
	'secret_live_[0\-9A\-Za\-z\-_\-]{32}'
	'cloudinary://[0\-9]{15}:[0\-9A\-Za\-z\-_\-]{27}'
	'sk.ey[0\-9A\-Za\-z\-_.\-]{81}'
	'xox.\-[0\-9]{12}\-[0\-9]{12}\-[0\-9]{12}\-[a\-zA\-Z0\-9]{32}'
	'https://hooks.slack.com/services/T[a\-zA\-Z0\-9_]{8}/B[a\-zA\-Z0\-9_]{8}/[a\-zA\-Z0\-9_]{24}'
	'\"acc_private_key\"\>[0\-9a\-f]{40}'
	'[0\-9a\-f]{36}NRAL'
	"(?i)linkedin(.{0,20})?(?\-i)['\"][0\-9a\-z]{12}['\"]"
	"(?i)linkedin(.{0,20})?['\"][0\-9a\-z]{16}['\"]"
	"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0\-9A\-F]{8}\-[0\-9A\-F]{4}\-[0\-9A\-F]{4}\-[0\-9A\-F]{4}\-[0\-9A\-F]{12}"
	'[0\-9A\-Za\-z\+\=]{40\,50}'
	'://[a\-zA\-Z0\-9]+:[a\-zA\-Z0\-9]+@[a\-zA\-Z0\-9]+.[a\-zA\-Z]+'
)
desc=(
	'Generic Google API Key. Often intentionally made public in Android apps, but worth manual investigation. The keys might be sensitive or improperly restricted.'
	'Google OAuth Access Token. Can be used to access Google APIs.'
	'Google ReCAPTCHA Key. Might be the secret key.'
	'Google Cloud Platform API key. Can be used to access different Google services, depending on the key and its permissions.'
	'Amazon AWS Access Key ID. Not really considered a secret, but if it is leaked, the secret key might be as well...'
	'Amazon AWS Secret Key. Amazon AWS credential. Its permissions can be enumerated using the enumerate-iam tool.'
 	'Amazon MWS Auth token. Can be used to access the affected Amazon MWS account.'
	'Facebook Access Token.'
	'Facebook Secret Key'
	'Twitter Secret Key.'
	'Mailgun API Key. Can be used to access the affected Mailgun account.'
	'MailChimp API Key. Can be used to access the affected MailChimp account.'
	'Twilio API Key. Can be used to access the affected Twilio account.'
	'PayPal Braintree Access Token.'
	'Square Access Token. Can be used to gain access to the affected Square account.'
	'Square OAuth Secret.'
	'Stripe Standard API key.'
	'Stripe Restricted API key.'
	'Picatic API Key. Used to access the Picatic API.'
	'Github Access Token. Can be used to access the affected GitHub account.'
	'Branch SDK Key. While not considered secret, it can be used to create deeplinks to arbitrary URLs on the associated domain if not restricted. Depending on the context, this could be considered a security issue.'
	'Branch Secret Access Key. Can be used as Branch.io credentials.'
	'Cloudinary URL containing API Key and Secret. Can be used as HTTP Basic Auth credentials to access the affected account.'
	'Mapbox Secret Access Token. Can be used to access the affected Mapbox account.'
	'Slack API Token. Reference Can be used as credential to access a Slack instance.'
	'Slack Webhook URL.'
	'Accengage Partner ID and Private Key. The ID is next to the private key in the strings.xml file. These values should be removed from strings.xml, but do not pose a significant risk by themselves, since username/password authentication is required to use the API anyway.'
	'New Relic License Key. Can be used to send fake metric data to the affected account. According to New Relic documentation, it should be treated like a password.'
	'LinkedIn Client ID'
	'LinkedIn Secret Key.'
	'Heroku API Key. Used as the Authorization bearer token in API calls to api.heroku.com.'
	'Microsoft Azure Tenant Client Secret. Look for the client id and tenant id.'
	'URL containing HTTP Basic Authentication credentials.'
)

if [ "$#" -ne 1 ] # defaults target directory to current directory if no argument is supplied
then
    dir="./"
else
    dir=$1
fi

if [ ! -d $dir ]
    then
        printf "[!] Directory not found."
        exit 1
fi

index=0
for i in ${regexs[@]}
do
    findings=$(grep -iR -s -v -e "base64" -e "SHA-256-Digest" $dir | egrep -so $i | sort -u) # search for secrets, filter false positives, grab only the tokens, and filter duplicates
    if [ ! -z "$findings" ] # if we found something, print it with the relevant info
    then
        printf "[*] ${names[index]}(s) found:\n$findings\n\nDescription: ${desc[index]}\n\n\n"
    fi
    ((index=index+1))
done

printf "[i] Scan completed.\n"

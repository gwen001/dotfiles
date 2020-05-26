
function quicksub() {
  tmpfile="$(date "+%s")"
  threatcrowd $1 >> $tmpfile
  certspotter $1 >> $tmpfile
  crtsh $1 >> $tmpfile
  bufferover $1 >> $tmpfile
  cat $tmpfile | grep -v "*" | sort -fu
  rm $tmpfile
}

function sslinfo() {
  timeout 3 openssl s_client -showcerts -servername $1 -connect $1:443 <<< "Q" | openssl x509 -text -noout
}
function sslsub() {
  timeout 3 openssl s_client -showcerts -servername $1 -connect $1:443 <<< "Q"  2>/dev/null | openssl x509 -text -noout | grep DNS | tr ',' '\n' | cut -d ':' -f 2 | sort -fu
}

function apksign {
  jarsigner -keystore ~/Android/debug.keystore -verbose -storepass android -keypass android -sigalg SHA1withDSA -digestalg SHA1 "$1" androiddebugkey
}

s3ls(){
aws s3 ls s3://$1
}

s3cp(){
aws s3 cp $2 s3://$1 
}


function ejs() {
   URL=$1;
   curl -Lks -m 5 $URL | tac | sed "s#\\\/#\/#g" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=$URL '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"\n##### %\";wget --timeout=3 --no-check-certificate --quiet \"%\"; basename \"%\" | xargs -I \"#\" sh -c 'linkfinder.py -o cli -i # 2>/dev/null'"

#  curl -Lks -m 5 "$1" | tac | sed "s#\\\/#\/#g" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | awk -F '//' '{if(length($2))print "https://"$2}' | sort -fu | xargs -I '%' sh -c "echo \"'##### %\";curl -k -s \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"('#####.*)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\" | sort -fu" | awk -F "['\"]" '{print $2}'

#  curl -Lks -m 5 "$1" | tac | sed "s#\\\/#\/#g" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | awk -F '//' '{if(length($2))print "https://"$2}' | sort -fu | xargs -I '%' sh -c "curl -Lks -m 5 \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"(\>\>\>)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\"" | awk -F "['\"]" '{print $2}' | sort -fu
}

function oparam {
  echo $1 | tr '?' '&' | awk -F '&' '{for(i=2;i<=NF;i++){split($i,t,"=");print t[1]}}' | sort -fu
}
function oparamv {
  echo $1 | tr '?' '&' | awk -F '&' '{for(i=2;i<=NF;i++){split($i,t,"=");print t[2]}}' | sort -fu
}
function oparams {
  cat $1 | parallel -j 10 "echo {1} | tr '?' '&' | awk -v fmt='=' -F '&' '{for(i=2;i<=NF;i++){split(\$i,t,fmt);print t[1];}}'"
  #cat $1 | parallel -j 100 echo {1} | tr '?' '&' | awk -F '&' '{for(i=2;i<=NF;i++){split($i,t,"=");print t[1]}}'
  #while read u; do echo $u | tr '?' '&' | awk -F '&' '{for(i=2;i<=NF;i++){split($i,t,"=");print t[1]}}'; done < $1
}
function oparamsv {
  cat $1 | parallel -j 10 "echo {1} | tr '?' '&' | awk -v fmt='=' -F '&' '{for(i=2;i<=NF;i++){split(\$i,t,fmt);print t[2];}}'"
  #while read u; do echo $u | tr '?' '&' | awk -F '&' '{for(i=2;i<=NF;i++){split($i,t,"=");print t[2]}}'; done < $1
}
function oasn {
  grep -i $1 /home/gwen/Security/tools/Discovery/Ip/asnlookup/GeoLite2-ASN-Blocks-IPv4.csv | cut -d "," -f 2 | sort -fu
}
function oasnr {
  grep -i $1 /home/gwen/Security/tools/Discovery/Ip/asnlookup/GeoLite2-ASN-Blocks-IPv4.csv | cut -d "," -f 1 | sort -fu
}
function otestu {
  cat $1 | parallel -j 20 -I# 'echo "$(printf "%-100s" "#") -> $((curl -I -s -m 5 -k "#"||echo KO)|head -n 1 -)"'
  #while read u;do echo "$(printf '%-100s' "$u")-> $((curl -I -s -m 5 -k "$u"||echo KO)|head -n 1 -)";done < $1
}
function otestuj {
  cat $1 | tac | tac | jq -r '.[]'|grep 'http'|cut -d '"' -f 2 | parallel -j 20 -I# 'echo "$(printf "%-100s" "#") -> $((curl -I -s -m 5 -k "#"||echo KO)|head -n 1 -)"'
  #while read u;do echo "$(printf '%-100s' "$u")-> $((curl -I -s -m 5 -k "$u"||echo KO)|head -n 1 -)";done < $1
}
function oopen {
  f=$1
  #cat $f | awk '{print ($1 ~ "://") ? $1 : "http://"$1"\nhttps://"$1}' | xargs firefox
  firefox `cat $f | awk '{if(index($1,"http")){print $1}else{print "http://"$1;print "https://"$1}}' | tr "\n" " "`
}
function ohost {
  host `echo $1|sed "s/.*:\/\///"|cut -d '/' -f 1|cut -d '@' -f 2|cut -d':' -f 1`
}
function ohosts {
  while read u; do host `echo $u|sed "s/.*:\/\///"|cut -d '/' -f 1|cut -d '@' -f 2|cut -d':' -f 1`; done < $1
}
function osub {
  curl -siLk -m 5 https://$1|egrep -io "[0-9a-z_\-\.]+\.([0-9a-z_\-]+)?`echo $1|awk -F '.' '{print $(NF-1)}'`([0-9a-z_\-\.]+)?\.[a-z]{1,5}"|sort -fu
}
function osubs {
  while read h; do curl -siLk -m 5 https://$h|egrep -io  "[0-9a-z_\-\.]+\.([0-9a-z_\-]+)?`echo $h|awk -F '.' '{print $(NF-1)}'`([0-9a-z_\-\.]+)?\.[a-z]{1,5}"|sort -fu ; done < $1
}
function olink {
  curl -siLk -m 5 https://$1|sed -n -E "s/.*(href|src|url)[=:]['\"]?([^'\">]+).*/\2/p"
}
function olinks {
  while read h; do curl -siLk -m 5 https://$h|sed -n -E "s/.*<.*(href|src|url)[=:]['\"]?([^'\">]+).*/\2/p" ; done < $1
}

certspotter(){ 
  output=$(curl -ks -m 5 "https://certspotter.com/api/v0/certs?domain=$1" | tac | tac | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u)
  if [ $# -gt 1 ] ; then
    echo $output | tr " " "\n"
  else
    echo $output | tr " " "\n" | grep $1
  fi
}
certspotters(){
  while read domain; do 
    output = $(curl -ks -m 5 "https://certspotter.com/api/v0/certs?domain=$domain" | tac | tac | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u)
    if [ $# -gt 1 ] ; then
      echo $output | tr " " "\n"
    else
      echo $output | tr " " "\n" | grep $domain
    fi
  done < $1
}

threatcrowd(){
  domain=$1
  dom="%.$domain"
  curl -s -k -m 5  "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq .subdomains | grep '"' | cut -d '"' -f 2 | sort -fu
}

bufferover(){
  domain=$1
  dom="%.$domain"
  curl -s -k -m 5  "https://dns.bufferover.run/dns?q=.$domain" | jq .FDNS_A | grep '"' | cut -d '"' -f 2 | sort -fu
}

crtsh(){
  domain=$1
  dom="%.$domain"
  curl -k -s -m 5 "https://crt.sh/?q=$dom&output=json" | tr ',' "\n" | grep name_value | awk -F '"' '{print $4}' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\\n/\n/g' | sort -u
}
crtshs(){
  while read domain; do 
      dom="%.$domain"
      curl -k -s -m 5 "https://crt.sh/?q=$dom&output=json" | tr ',' "\n" | grep name_value | awk -F '"' '{print $4}' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\\n/\n/g' | sort -u
  done < $1
}

securitytrails(){
  domain=$1
  curl -k -s -m 5 --url "https://api.securitytrails.com/v1/domain/$domain/subdomains" -H "apikey: $SECURITY_TRAILS" | tac | tac | grep -v '/v1/domain/' | grep '"' | awk -F '"' '{print $2}' | sort -fu | awk -v dom=$domain '{print $1"."dom}'
}

c99(){
  domain=$1
  curl -k -s -m 5 "https://subdomainfinder.c99.nl/scans/2020-04-04/$domain" | egrep -ho "[a-zA-Z0-9_\.\-]+\.[a-zA-Z0-9_\.\-]*$domain" | sort -fu
}

gggithub() {
  domain=$1
  google-search.py -t "site:github.com $domain" -b -d -s 0 -e 30 | sed -r "s#//github.com/(.*)/blob/#//raw.githubusercontent.com/\1/#g" | xargs -I '%' sh -c "curl -Lks -m 5 '%' | egrep -o \"[a-zA-Z0-9_\.\-]+\.$domain\""
}

ggpastebin() {
  domain=$1
  google-search.py -t "site:pastebin.com $domain" -b -d -s 0 -e 30 | sed "s/\.com\//\.com\/raw\//" | xargs -I '%' sh -c "curl -Lks -m 5 '%' | egrep -o \"[a-zA-Z0-9_\.\-]+\.$domain\""
}

wordgrab() {
  url=$1
  tmpfile="$(date "+%s")"
  curl -sLk -m 5 -A "Mozilla/5.0 (X11; Linux; rv:74.0) Gecko/20100101 Firefox/74.0" http://$url | html2text | egrep -io "[0-9a-zA-Z\-]+" | tr '[:upper:]' '[:lower:]' | sed -r "s/^[^a-z]+//g" | sed -r "s/[^a-z0-9]+$//g" | sort -fu | tee -a $tmpfile | tr '-' '.'  | tee -a $tmpfile | tr "." "\n" >> $tmpfile
  cat $tmpfile | sort -fu | sed -r '/.{3,}/!d'
  rm $tmpfile
}
wordgrab2() {
  url=$1
  cewl.rb -u "Mozilla/5.0 (X11; Linux; rv:74.0) Gecko/20100101 Firefox/74.0" -d 0 -m 5 https://www.$1 | tr '[:upper:]' '[:lower:]' |sort -fu | grep -v "robin wood"
}

ipinfo(){
  curl -ks -m 5 http://ipinfo.io/$1
}

myip() {
  curl -ks -m 5 ifconfig.me
  echo
}

fsu() {
  cat $1 | sort -fu > /tmp/aaa
  mv /tmp/aaa $1
}

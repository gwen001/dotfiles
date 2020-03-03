
s3ls(){
aws s3 ls s3://$1
}

s3cp(){
aws s3 cp $2 s3://$1 
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
  cat $1 | jq -r '.[]'|grep 'http'|cut -d '"' -f 2 | parallel -j 20 -I# 'echo "$(printf "%-100s" "#") -> $((curl -I -s -m 5 -k "#"||echo KO)|head -n 1 -)"'
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
  curl -siL https://$1|egrep -io "[0-9a-z_\-\.]+\.([0-9a-z_\-]+)?`echo $1|awk -F '.' '{print $(NF-1)}'`([0-9a-z_\-\.]+)?\.[a-z]{1,5}"|sort -fu
}
function osubs {
  while read h; do curl -siL https://$h|egrep -io  "[0-9a-z_\-\.]+\.([0-9a-z_\-]+)?`echo $h|awk -F '.' '{print $(NF-1)}'`([0-9a-z_\-\.]+)?\.[a-z]{1,5}"|sort -fu ; done < $1
}
function olink {
  curl -siL https://$1|sed -n -E "s/.*(href|src|url)[=:]['\"]?([^'\">]+).*/\2/p"
}
function olinks {
  while read h; do curl -siL https://$h|sed -n -E "s/.*<.*(href|src|url)[=:]['\"]?([^'\">]+).*/\2/p" ; done < $1
}

certspotter(){ 
  output=$(curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u)
  if [ $# -gt 1 ] ; then
    echo $output | tr " " "\n"
  else
    echo $output | tr " " "\n" | grep $1
  fi
} #h/t Michiel Prins
certspotters(){
  while read domain; do 
    output = $(curl -s https://certspotter.com/api/v0/certs\?domain\=$domain | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u)
    if [ $# -gt 1 ] ; then
      echo $output | tr " " "\n"
    else
      echo $output | tr " " "\n" | grep $domain
    fi
  done < $1
}

crtsh(){
  domain=$1
  dom=$domain
  #for i in $(seq 0 10); do
    dom="%.$dom"
    #echo $dom
    curl -s https://crt.sh/?q\=$dom\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | grep $domain | sort -u
  #done
}
crtshs(){
  while read domain; do 
    dom=$domain
    #for i in $(seq 0 10); do
      dom="%.$dom"
      #echo $dom
      curl -s https://crt.sh/?q\=$dom\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | grep $domain | sort -u
    #done
  done < $1
}

ipinfo(){
  curl http://ipinfo.io/$1
}

myip() {
  curl ifconfig.me
  echo
}

fsu() {
  cat $1 | sort -fu > /tmp/aaa
  mv /tmp/aaa $1
}

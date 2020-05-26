
alias ..='cd ..'
alias l='ls -lhF --color=auto'
alias ll='ls -lahF --color=auto'
alias df='df -h'
alias less='less -I -N -R'
alias rsync='rsync -h --progress'
alias wget='wget --no-check-certificate'
alias p='ps auxf'
alias vbm='vboxmanage'
alias grep='grep --color'
alias du1='du -h --max-depth=1'
alias as='aptitude search'
alias ai='aptitude install'
alias ap='aptitude purge'
alias ass='dpkg -l | grep -i'
alias dpkgs='dpkg -l | grep -i'
alias sar='service apache2 restart'
alias h='host'
alias ha='host -t any'

alias gc='git clone'
alias gs='git status'
alias gp='git pull'
alias gb='git branch'
alias gba='git branch -av'

alias gip='grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"'

alias ps1="PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"
alias ps2="PS1='\[\033[01;32m\]\$\[\033[00m\] '"

alias vrec='recordmydesktop --no-sound -o ~/Bureau/out.ogv'
alias vconv='ffmpeg2theora -i ~/Bureau/out.ogv -vcodec mpeg4 -sameq --noaudio -v 8 -x 1360 -y 768 ~/Bureau/out.avi; mv ~/Bureau/out.ogv.ogv ~/Bureau/out.avi'
alias mxmlc='/opt/flex_sdk_4.6.0.23201B/bin/mxmlc'
alias ccc='php /home/gwen/Documents/clean_unbreakable_space.php'

alias kk='/home/gwen/Documents/mykillall.sh'
alias ac='/home/gwen/.local/autochrome/chrome --profile-directory=Yellow 2>/dev/null &'
alias nse='ls /usr/share/nmap/scripts/ | grep'

alias json-beautifier='python -m json.tool'

alias w='cd /var/www/html/'
alias b='cd ~/Bureau/'
alias d='cd ~/Documents/'
alias t='cd ~/Téléchargements/'
alias s='cd ~/Security/'
alias bb='cd ~/Security/bug-bounty/'
alias pp='cd ~/Security/mytools/pentest-tools/'

#alias bs='java -jar /home/gwen/Sécurité/tools/allinone/burp/burpsuite_pro_v1.7.17.jar &'
#alias burp='java -jar /home/gwen/Sécurité/tools/allinone/burp/burpsuite_pro_v1.7.17.jar &'
#alias zde='/opt/Zend/ZendStudio-5.5.1/bin/ZDE'
alias ast='/opt/android-studio/bin/studio.sh &'
alias em='~/Android/Sdk/emulator/emulator -avd Pixel_XL_API_22 -http-proxy http://127.0.0.1:8080 &'

#alias jekpb='bundle exec jekyll b --config _config.yml,_config_prod.yml'
#alias jekps='bundle exec jekyll s --config _config.yml,_config_prod.yml'
#alias jekdb='bundle exec jekyll b --config _config.yml,_config_dev.yml'
#alias jekds='bundle exec jekyll s --config _config.yml,_config_dev.yml'

#alias wer='web-ext run --firefox-profile=/home/gwen/.mozilla/firefox/sb3pgl94.default/'

alias copy='xclip -selection c'
alias sj='subjack -a -t 20 -timeout 20 -ssl -c "/opt/SecLists/mine/subjack_fingerprints.json" -v -w '

alias neofetch='neofetch --config off --bold off --colors 11 1 8 8 8 7'

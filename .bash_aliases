
alias ..='cd ..'
alias l='ls -lhF --color=auto'
alias ll='ls -lahF --color=auto'
alias df='df -h'
alias less='less -I'
alias rsync='rsync -h --progress'
alias wget='wget --no-check-certificate'
alias p='ps auxf'
alias vbm='vboxmanage'
alias grep='egrep --color'

alias as='aptitude search'
alias ai='aptitude install'
alias ap='aptitude purge'
alias ass='dpkg -l | grep -i'
alias dpkgs='dpkg -l | grep -i'
alias sar='service apache2 restart'

alias w='cd /var/www/html'
alias b='cd ~/Desktop'
alias d='cd ~/Documents'
alias t='cd ~/Downloads'
alias s='cd ~/Security'
alias bb='cd ~/Security/bugbounty'
alias pp='cd ~/Security/mytools/pentest-tools/'

alias gc='git clone'
alias gs='git status'
alias gp='git pull'
alias gb='git branch'
alias gba='git branch -av'

alias gip='grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"'

alias ps1="PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"
alias ps2="PS1='\[\033[01;32m\]\$\[\033[00m\] '"

alias vrec='recordmydesktop --no-sound -o ~/Desktop/out.ogv'
alias vconv='ffmpeg2theora -i ~/Desktop/out.ogv -vcodec mpeg4 -sameq --noaudio -v 8 -x 1360 -y 768 ~/Desktop/out.avi; mv ~/Desktop/out.ogv.ogv ~/Desktop/out.avi'
alias mxmlc='/opt/flex_sdk_4.6.0.23201B/bin/mxmlc'
alias ccc='php /home/gwen/Documents/clean_unbreakable_space.php'

alias kk='/home/gwen/Documents/mykillall.sh'
alias ac='/home/gwen/.local/autochrome/chrome --profile-directory=Yellow 2>/dev/null &'
alias nse='ls /usr/share/nmap/scripts/ | grep'

alias json-beautifier='python -m json.tool'

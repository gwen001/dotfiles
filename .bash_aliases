
alias ..='cd ..'
alias l='ls -lhF'
alias ll='ls -lahF'
alias df='df -h'
alias less='less -I -N -R'
alias rsync='rsync -h --progress'
alias wget='wget --no-check-certificate'
alias p='ps aux'
alias grep='egrep --color '
alias du1='du -h -d 1'
alias as='aptitude search'
alias ai='aptitude install'
alias ass='dpkg -l | grep -i'
alias dpkgs='dpkg -l | grep -i'
alias h='host'
alias htop='htop -s PERCENT_CPU'
alias sr='screen -R'
alias sls='screen -ls'

alias sar='sudo brew services stop httpd ; sudo brew services start httpd'

alias gc='git clone'
alias gs='git status'
alias gp='git pull'
alias gb='git branch'
alias gba='git branch -av'
alias ghr='~/security/mytools/github-release.sh'

alias b='cd ~/Desktop/'
alias d='cd ~/Documents/'
alias t='cd ~/Downloads/'
alias s='cd ~/security/'
alias w='cd ~/Public/'
alias bb='cd ~/security/bugbounty/'
alias pp='cd ~/security/mytools/pentest-tools/'

alias gip='grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"'

alias ps1="PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '"
alias ps2="PS1='\[\033[01;32m\]\$\[\033[00m\] '"

alias burp='/Users/gwen/security/burp/burponmac.sh'
alias kk='/home/gwen/Documents/mykillall.sh'
alias ac='/Users/gwen/Applications/Chromium.app/Contents/MacOS/Chromium --profile-directory=Green 2>/dev/null &'

#alias bs='java -jar /home/gwen/Sécurité/tools/allinone/burp/burpsuite_pro_v1.7.17.jar &'
#alias burp='java -jar /home/gwen/Sécurité/tools/allinone/burp/burpsuite_pro_v1.7.17.jar &'
alias wpscan="wpscan --rua -e --api-token $WPSCAN_TOKEN --url "


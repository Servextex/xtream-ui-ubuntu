`cd $HOME`

`sudo yum -y remove rpmdevtools`

`sudo yum -y install devscripts pbuilder wget ca-certificates`

`sudo apt-get -y install pbuilder debhelper cdbs lintian build-essential fakeroot devscripts dh-make dput wget ca-certificates`

`sudo wget -O /etc/pbuilder/ubuntu-jammy-amd64 https://github.com/Servextex/xtream-ui-ubuntu/raw/main/ubuntu/src/pbuilder/ubuntu-jammy-amd64`

`sudo pbuilder create --configfile /etc/pbuilder/ubuntu-jammy-amd64`

`sudo pbuilder update --override-config --configfile /etc/pbuilder/ubuntu-jammy-amd64`

`sudo pbuilder login --configfile /etc/pbuilder/ubuntu-jammy-amd64`

`wget -O $HOME/build-freetype.sh https://github.com/Servextex/xtream-ui-ubuntu/raw/main/ubuntu/src/Ubuntu/22.04/xtreamui-freetype2/build.sh`

`sudo bash $HOME/build-freetype.sh`

`rm -f $HOME/build-freetype.sh`


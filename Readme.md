# DNAS Bypass

This is a project to bypass the DNAS check for online PS2 games.


## Clone Project

```
git clone https://github.com/Project-Backstab/BF2MC-Matchmaker.git
cd BF2MC-Matchmaker

git submodule init
git submodule update

sudo apt-get install libmysqlclient-dev
```

Monitor network
```
sudo tcpdump -D
sudo tcpdump --interface any port 443 -w dump.pcap
```

Compile openssl 1.0.2q
```
mkdir download
cd download
wget https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_2q.tar.gz

cd ..
mkdir temp
cd temp
tar xvfz ../download/OpenSSL_1_0_2q.tar.gz

cd openssl-OpenSSL_1_0_2q
./Configure --prefix=$PWD/../../libs/openssl-1.0.2q linux-x86_64 enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers
make depend
make -j 4
make install
```

Check:
```
cd libs/openssl-1.0.2q/bin
./openssl ciphers -V ALL | grep DES-CBC3-SHA
```

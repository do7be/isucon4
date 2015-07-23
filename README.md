## install redis
```
$ sudo yum --enablerepo=epel -y install redis
```

## install lib
```
$  wget http://mirror.centos.org/centos/6/SCL/x86_64/scl-utils/scl-utils-20120927-11.el6.centos.alt.x86_64.rpm
$  sudo rpm -ivh scl-utils-20120927-11.el6.centos.alt.x86_64.rpm
$  sudo yum install php56-pecl-igbinary
$  wget http://rpms.famillecollet.com/enterprise/remi-release-6.rpm
$  sudo rpm -ivh remi-release-6.rpm
$  sudo yum --enablerepo=remi,remi-php56 install php56-php-pecl-redis.x86_64
$  ls /opt/remi/php56/root/usr/lib64/php/modules/redis.so
$  sudo ln -s /opt/remi/php56/root/usr/lib64/php/modules/redis.so /usr/lib64/php/modules/redis.so 
$  php -i | grep -i redis

$ vi .local/php/etc/php.ini

extension_dir = /usr/lib64/php/modules/
extension = redis.so
```
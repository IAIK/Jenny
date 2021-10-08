# get path of this makefile
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))

.PHONY: all
all: ../nginx/objs/nginx ../nginx_native/objs/nginx .config_done /tmp/www/index.html

# separate target for /tmp stuff because we may or may not start with a clean /tmp tmpfs
/tmp/www/index.html:
	sudo mkdir -p /tmp/www
	sudo chown -R $(USER): /tmp/www
	touch /tmp/www/index.html
	echo "test" > /tmp/www/index.html

.config_done: /tmp/www/index.html
	sudo mkdir -p /usr/local/nginx/conf
	sudo mkdir -p /usr/local/nginx/logs
	sudo chown -R $(USER): /usr/local/nginx/
	cp ../nginx_aux/conf/* /usr/local/nginx/conf/
	openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /usr/local/nginx/conf/cert.key -out /usr/local/nginx/conf/cert.crt -subj "/C=US/ST=.../L=... /O=.../OU=.../CN=.../emailAddress=..."
	sudo htpasswd -b -c /usr/local/nginx/conf/htpasswd user1 pass1
	sudo chmod -R g+rw /usr/local/nginx
	touch $@

.PHONY: test
test: ../nginx_native/objs/nginx ../nginx/objs/nginx .config_done
	killall nginx || true
	../nginx_native/objs/nginx &  sleep 0.2 && curl -k                                                   http://localhost:3000/index.html     |           grep '^test$$' && killall nginx
	../nginx_native/objs/nginx &  sleep 0.2 && curl -k                                                   http://localhost:3000/index.html     |           grep '^test$$' && killall nginx
	../nginx_native/objs/nginx &  sleep 0.2 && curl -k                -H "Accept-Encoding: deflate,gzip" http://localhost:3000/index.html     | gzip -d | grep '^test$$' && killall nginx
	../nginx_native/objs/nginx &  sleep 0.2 && curl -k -u user1:pass1 -H "Accept-Encoding: deflate,gzip" http://localhost:3000/api/index.html | gzip -d | grep '^test$$' && killall nginx
	../nginx_native/objs/nginx &  sleep 0.2 && curl -k -u user1:pass1                                    http://localhost:3000/api/index.html |           grep '^test$$' && killall nginx
	killall nginx || true

../nginx/objs/nginx:
	cd ../nginx && ./auto/configure --with-threads --with-http_ssl_module --with-http_gzip_static_module
	cp patch/objs/Makefile ../nginx/objs/
	make -C ../nginx -j16

../nginx_native/objs/nginx:
	cd ../nginx_native && ./auto/configure --with-threads --with-http_ssl_module --with-http_gzip_static_module
	make -C ../nginx_native -j16


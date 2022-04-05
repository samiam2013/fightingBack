# makitios mars
some code for finding links in nginx logs to configure a proxy rewrite rule to [a honeypot I'm working on](https://github.com/samiam2013/pugnasAres)

you can reach ares [through another tool, cephissus](https://cephissus.myres.dev) at links [like this one](https://cephissus.myres.dev/admin/pma) where the sort.pl output is used to regex-redirect your alleged malintended request to the honeypot/random byte dumper with NGINX

## example config
```nginx
location ~* ^/(my)?admin(\/(db|index|pma|phpmyadimin|sqladmin|web)|istrator\/(pma|admin|php))?/ {
	# auto generated proxy to honeypot
	proxy_pass http://localhost:3001$request_uri;
}

location ~* ^/(pma|(_|[\d])?php|database|(shop)?db|(my)?sql|xmlrpc)/ {
	# auto generated proxy to honeypot
	proxy_pass http://localhost:3001$request_uri;
}
```

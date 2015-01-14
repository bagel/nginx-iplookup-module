nginx-iplookup-module
========================

nginx iplookup module

##nginx

####nginx location iplookup config
	
	location /iplookup/extra {
	        iplookup "/usr/local/share/iplookup/ip.db";
	        iplookup_extra on;
	}
	


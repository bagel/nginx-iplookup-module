nginx-iplookup-module
========================

nginx iplookup module

####iplookup config
	
	location /iplookup/extra {
	        iplookup "/usr/local/share/iplookup/ip.db";
	        iplookup_extra on;
	}
	


pbproxy : pbproxy.c
	gcc pbproxy.c -o pbproxy -lcrypto 

raunak_shah_hw3.tar.gz : pbproxy report.txt keyfile.txt Makefile
	tar -czf ./raunak_shah_hw3.tar.gz ./pbproxy.c ./keyfile.txt ./Makefile ./report.txt

ALL : pbproxy raunak_shah_hw3.tar.gz

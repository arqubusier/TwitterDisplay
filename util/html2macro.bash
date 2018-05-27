#!/bin/bash

len=`cat $1 |unix2dos | wc -c |awk '{printf "%s", $1}'`

echo "#define $2 "'"HTTP/1.1 200 OK\r\n" \'
echo '"Content-Type: text/html\r\n" \'
echo '"Content-Length: '$len' \r\n\r\n" \'
sed 's/\"/\\\"/g;s/^/\"/;s/$/\\r\\n\" \\/' $1            

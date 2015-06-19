### My HTTP flow ###
TCP assembling / HTTP assmebling, support HTTP pipeling

### Example ###

./main xx.pcap

<pre>
-- Packet size: 494, Time: 1394682304, Tuple: 192.168.56.1:40968:192.168.56.178:80
GET /wp37/wp-content/themes/twentythirteen/images/search-icon.png HTTP/1.1
Host: ubuntu32
Connection: keep-alive
Accept: image/webp,*/*;q=0.8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit (KHTML, like Gecko) Chrome Safari
Referer: http://ubuntu32/wp37/
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,fr;q=0.6,zh-CN;q=0.4,zh;q=0.2,zh-TW;q=0.2,hr;q=0.2


-- End Packet --
</pre>

### Compile ###

On Mac OS, 

<pre>
make mac
</pre>

On Linux (static),

<pre>
make
</pre>

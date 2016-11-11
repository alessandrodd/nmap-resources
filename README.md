# nmap-resources
Various resources for nmap

**Nmap HTTP Title Matcher**

Finds web servers that matches a certain LUA regular expression in the default page's title OR in the hostname retrieved by reverse DNS, if the relative option is provided.

If http-title-matcher.no-redirect is not provided, the script will follow up to 5 HTTP redirects, using the default rules in the
http library.

HTTPS is transparently supported.

Based on Diman Todorov's http-title script (all thanks to him)

***example:*** 

    sudo nmap -p 80,443 192.168.0.0/16 --min-hostgroup 4096 --min-parallelism 1024 --script=./http-title-matcher --script-args 'http-title-matcher.match=hello world, http-title-matcher.case-insensitive' -oX my_scan_dump.xml

     - *-p 80,443*  =>  scan ports 80 and 443 (default for HTTP and HTTPS)
     - *192.168.0.0/16*  =>  scan subnet 
     - *--min-hostgroup 4096 --min-parallelism 1024*  =>  maximize parallel execution (set lower values or omit for more reliability)
     - *--script=./http-title-matcher*  =>  load http-tite-matcher script from the current folder
     - *--script-args 'http-title-matcher.match=hello world, http-title-matcher.case-insensitive'*  =>  match any website that contains "hello world" in the title, case insensitive
     - *-oX my_scan_dump.xml*  =>  save results in an handy xml file


Details:

        --@args http-title-matcher.match LUA Regular expression to match in the HTTP server title (OR DNS reversed hostname, if http-title-matcher.check-hostname is provided). Case INSENSITIVE. Default: match anything
        --      http-title-matcher.case-insensitive Makes the match case-insensitive.
        --      http-title-matcher.url The url to fetch. Default: /
        --      http-title-matcher.no-redirect Add if the script shouldn't follow redirects.
        --      http-title-matcher.check-hostname Check the hostname retrieved by reverse DNS in addition to the title for matches.
        --@output
        -- Nmap scan report for scanme.nmap.org (74.207.244.221)
        -- PORT   STATE SERVICE
        -- 80/tcp open  http
        -- |_http-title-matcher: Go ahead and ScanMe!
        --
        -- @xmloutput
        -- <elem key="title">Go ahead and ScanMe!</elem>
        -- @xmloutput
        -- <elem key="title">Wikipedia, the free encyclopedia</elem>
        -- <elem key="redirect_url">http://en.wikipedia.org/wiki/Main_Page</elem>
    
    author = "Alessandro Di Diego"
    
    license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
    
    categories = {"default", "discovery", "safe"}

`

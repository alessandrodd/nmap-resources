local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Finds web servers that matches a certain LUA regular expression in the default page's title OR in the hostname retrieved by reverse DNS, if the relative option is provided.

If http-title-matcher.no-redirect is not provided, the script will follow up to 5 HTTP redirects, using the default rules in the
http library.

HTTPS is transparently supported.

Based on Diman Todorov's http-title script (all thanks to him)

example: sudo nmap -p 80,443 192.168.0.0/16 --min-hostgroup 4096 --min-parallelism 1024 --script=./http-title-matcher --script-args 'http-title-matcher.match=hello world, http-title-matcher.case-insensitive' -oX my_scan_dump.xml

-p 80,443 : scan ports 80 and 443 (default for HTTP and HTTPS)
192.168.0.0/16 : scan subnet 
--min-hostgroup 4096 --min-parallelism 1024 : maximize parallel execution (set lower values or omit for more reliability)
--script=./http-title-matcher : load http-tite-matcher script from the current folder
--script-args 'http-title-matcher.match=hello world, http-title-matcher.case-insensitive' : match any website that contains "hello world" in the title, case insensitive
-oX my_scan_dump.xml : save results in an handy xml file

]]

---
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


portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title, match, caseinsensitive, url, noredirects, checkhostname

  match = stdnse.get_script_args(SCRIPT_NAME..".match")
  caseinsensitive = stdnse.get_script_args(SCRIPT_NAME..".case-insensitive")
  url = stdnse.get_script_args(SCRIPT_NAME..".url")
  noredirects = stdnse.get_script_args(SCRIPT_NAME..".no-redirect")
  checkhostname = stdnse.get_script_args(SCRIPT_NAME..".check-hostname")
  
  resp = http.get( host, port, url or "/" )

  if not noredirects then
    -- check for a redirect
    if resp.location then
      redirect_url = resp.location[#resp.location]
      if resp.status and tostring( resp.status ):match( "30%d" ) then
        print(("Did not follow redirect to %s"):format( redirect_url ))
      end
    end
  end

  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")
  local newtitle = title
  local newhostname = host.name
  if(match ~= nil and caseinsensitive) then
    match = string.lower(match)
  end
  if(title ~= nil and caseinsensitive) then
    newtitle = string.lower(title)
  end
  if(host.name ~= nil and caseinsensitive) then
    newhostname = string.lower(host.name)
  end
  if match == nil or match == '' or (newtitle ~= nil and string.match(newtitle, match)) or (checkhostname and newhostname ~= nil and string.match(newhostname, match)) then

    print('\27[31m**********MATCH FOUND: ' .. host.ip .. '**********\27[0m')

    local display_title = title
    
    if display_title and display_title ~= "" then
      display_title = string.gsub(display_title , "[\n\r\t]", "")
      if #display_title > 65 then
        display_title = string.sub(display_title, 1, 62) .. "..."
      end
    else
      display_title = "Site doesn't have a title"
      if ( resp.header and resp.header["content-type"] ) then
        display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
      else
        display_title = display_title .. "."
      end
    end

    local output_tab = stdnse.output_table()
    output_tab.title = title
    output_tab.redirect_url = redirect_url

    local output_str = display_title
    if redirect_url then
      output_str = output_str .. "\n" .. ("Requested resource was %s"):format( redirect_url )
    end

    return output_tab, output_str
  else
    return nil
  end

end

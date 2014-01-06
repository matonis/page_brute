rule administrative_share_abuse
{
        meta:
                author="@matonis"
                description="syntax for accessing adminstrative shares"
        strings:
                $s0 = /(copy|del|psexec|net)/ nocase
                $s1 = "\\c$\\windows\\system32\\" nocase
                $s2 = "\\c$\\system32\\" nocase
                $s3 = "\\admin$\\" nocase
        condition:
                $s0 and (any of ($s1,$s2,$s3))
}

rule remote_system_syntax 
{
	meta:
		author = "@matonis"
		info = "Command syntax that is used to access remote systems by IP address"
	strings:
		$s1 = /\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
	condition:
		$s1
}

rule http_request_header
{
	meta:
		author="@matonis"
		description="HTTP header fields"
	strings:
		//methods
		$method0 = "OPTIONS"
		$method1 = "GET"
		$method2 = "HEAD"
		$method3 = "POST"
		$method4 = "PUT"
		$method5 = "DELETE"
		$method6 = "TRACE"
		$method7 = "CONNECT"

		//http version
		$version0 = "HTTP/1.1"
		$version1 = "HTTP/1.0"

		//headers
		$header0 = "Host: "
		$header1 = "User-Agent: "
		$header2 = "Content-Encoding: "
		$header3 = "Last-Modified: "
		$header4 = "Expires: "
		$header5 = "Connection: "
		$header6 = "Accept-Language: "
		$header7 = "Accept-Encoding: "
		$header8 = "Accet-Charset: "
		$header9 = "Cookie: "
		$header10 = "Content-Length: "
		$header11 = "Accept: "
	condition:
		(1 of ($method*)) and (1 of ($version*)) and (2 of ($header*))
}

rule http_response_header
{
	meta:
		author="@matonis"
		description="HTTP Response headers"
	strings:
		//Response Codes
		$response0 = "200 OK"
		$response1 = "201 Created"
		$response2 = "202 Accepted"
		$response3 = "203 Non-Authoritative Information"
		$response4 = "204 No Content"
		$response5 = "205 Reset Content"
		$response6 = "206 Partial Content"
		$response7 = "300 Multiple Choices"
		$response8 = "301 Moved Permanently"
		$response9 = "302 Found"
		$response10 = "303 See Other"
		$response11 = "304 Not Modified"
		$response12 = "305 Use Proxy"
		$response13 = "307 Temporary Redirect"
		$response14 = "400 Bad REQUEST"
		$response15 = "401 Unauthorized"
		$response16 = "403 Forbidden"
		$response17 = "404 Not Found"
		$response18 = "405 Method Not Allowed"
		$response19 = "406 Not Acceptable"
		$response20 = "407 Proxy Authentication Require"
		$response21 = "408 Request Timeout"
		$response22 = "409 Conflict"
		$response23 = "410 Gone"
		$response24 = "411 Length Required"
		$response25 = "412 Precondition Failed"
		$response26 = "413 Request Entity Too Large"
		$response27 = "414 Request-URI Too Long"
		$response28 = "415 Unsupported Media Type"
		$response29 = "416 Requested Range Not Satisfiable"
		$response30 = "417 Expectation Failed"
		$response31 = "500 Internal Server Error"
		$response32 = "501 Not Implemented"
		$response33 = "502 Bad Gateway"
		$response34 = "503 Service Unavailable"
		$response35 = "504 Gateway Timeout"
		$response36 = "505 HTTP Version Not Supported"

		//HTTP Versions
		$version0 = "HTTP/1.1"
		$version1 = "HTTP/1.0"

		//headers
		$field0 = "Set-Cookie:"
		$field1 = "Content-Type:"
		$field2 = "X-Powered-By:"
		$field3 = "Vary:"
		$field4 = "Transfer-Encoding:"
		$field5 = "Etag:"
		$field6 = "Date:"
		$field7 = "Server:"
		$field8 = "Cache-Control:"
		$field9 = "Connection:"
		$field10 = "Last-Modified:"
	condition:
		(1 of ($response*)) and (1 of ($version*)) and (2 of ($field*))
}

rule webartifact_html
{
	meta:
		author="@matonis"
		description="HTML identifiers"
	strings:
		//sepcific tags
		$html0 = "DOCTYPE"
		$html1 = "head>"
		$html2 = "body>"
		$html3 = "title>"
		$html4 = "body>"
		$html5 = "html>"
		$html6 = "</html>"
		$html7 = "<!--"
		$html8 = "-->"
		$html9 = "br>"
		$html10 = "script>"

	condition:
		2 of them
}

rule webartifact_javascript
{
	meta:
		author="@matonis"
		description="Javascript signature"
	strings:
		$java0 = "document.write" nocase
		$java1 = "createElement" nocase
		$java2 = "getElementsByTagName" nocase
		$java3 = "appendChild" nocase
		$java4 = "eval" nocase
		$java5 = "document.cookie" nocase
		$java6 = "p,a,c,k,e,d" nocase
		$java7 = ".substring"
	condition:
		3 of them
}

rule cmdshell
{
	meta:
		author="@matonis"
		description="Command prompt syntax to identify potential priv escalation"
	strings:
		$cmd0 = "C:\\Documents and Settings\\Administrator"
		$cmd2 = "C:\\Users\\Administrator"
	condition:
		any of them
}

rule webartifact_gmail
{
	meta:
		author="@matonis"
		description="Gmail artifacts"
	strings:
		$s1 = "[\"ms\","
		$s2 = "[\"ce\"]"
		$s3 = "[\"e\""
	condition:
		2 of them
}

rule social_security_syntax
{
	meta:
		author="@matonis"
		description="SSN Syntax"
	strings:
		$s1 = /[0-9]{3}-[0-9]{2}-[0-9]{3}/
	condition:
		$s1
}

rule smtp_fragments
{
	meta:
		author="@matonis"
		description="SMTP Artifacts"
	strings:
		$stmp0 = "HELO"
		$stmp1 = "MAIL FROM"
		$stmp2 = "RCPT TO"
		$stmp4 = "From:"
		$stmp5 = "To:"
		$stmp6 = "Cc:"
		$stmp7 = "Date:"
		$stmp8 = "Subject:"
		$stmp9 = "Delivered-To:"
		$stmp10 = "Received: by"
		$stmp11 = "Authentication-Results:"
		$stmp12 = "Return-Path:"
		$stmp13 = "Message-ID:"
		$stmp14 = "Content-Transfer-Encoding:"
		$stmp15 = "Content-Disposition:"
		$stmp16 = "X-Forwarded-To:"
		$stmp17 = "X-Forwarded-For:"
	condition:
		7 of them
}

rule irc
{
	meta:
		author="@matonis"
		description="IRC Artifacts"
	strings:
		$irc0="has joined #"
		$irc1 = "Channel created on"
		$irc2 = "USER"
		$irc3 = "PASS"
		$irc5 = "NICK"
		$irc6 = "CHANNEL"
		$irc7 = /are [0-9]* users and [0-9]* invisible on/
		$irc8 = /[0-9]* operator(s) online/

	condition:
		$irc0 or ($irc2 and $irc3 and $irc5 and $irc6) or $irc7 or $irc8 or $irc1
}

rule ftp
{
	meta:
		author="@matonis"
		description="FTP Command Artifacts"
	strings:
		$ftp1 = "150 File status okay; about to open data connection."
		$ftp2 = "150 Opening BINARY mode data connection for"
		$ftp3 = "150 Opening data connection."
		$ftp4 = "200 Command PORT okay."
		$ftp5 = "200 Command PROT okay."
		$ftp6 = "200 Command SITE okay."
		$ftp7 = "200 Command okay."
		$ftp8 = "200 EPRT command okay."
		$ftp9 = "200 Goodbye."
		$ftp10 = "200 PORT command successful."
		$ftp11 = "202 Already logged-in."
		$ftp12 = "202 Command ACCT not implemented."
		$ftp13 = "214 Help information."
		$ftp14 = "221 Goodbye."
		$ftp15 = "221 List of all the extensions supported."
		$ftp16 = "226 ABOR command successful."
		$ftp17 = "226 Closing data connection."
		$ftp18 = "226 Transfer complete."
		$ftp19 = "229 Entering passive mode"
		$ftp20 = "230 Already logged-in."
		$ftp21 = "230 User logged in, proceed."
		$ftp22 = "234 AUTH command okay; starting SSL connection."
		$ftp23 = "Transfer started."
		$ftp24 = "250 Command okay."
		$ftp25 = "250 Directory created."
		$ftp26 = "250 Directory removed."
		$ftp27 = "250 Requested file action okay, file renamed."
		$ftp28 = "331 Guest login okay, send your complete e-mail address as password."
		$ftp29 = "331 User name okay, need password."
		$ftp30 = "350 Requested file action pending further information."
		$ftp31 = "421 Maximum anonymous login limit has been reached."
		$ftp32 = "421 Maximum login limit has been reached."
		$ftp33 = "425 Can't open data connection."
		$ftp34 = "425 Cannot open data connection."
		$ftp35 = "425 Cannot open passive connection."
		$ftp36 = "425 Cannot open the data connection."
		$ftp37 = "426 Data connection error."
		$ftp38 = "431 Security is disabled."
		$ftp39 = "431 Service is unavailable."
		$ftp40 = "450 Can't delete file."
		$ftp41 = "450 No permission to delete."
		$ftp42 = "500 Execution failed."
		$ftp43 = "501 Syntax error in parameters or arguments."
		$ftp44 = "501 Syntax error."
		$ftp45 = "502 Command SITE not implemented for this argument."
		$ftp46 = "502 Not yet implemented."
		$ftp47 = "503 Cannot find the file which has to be renamed."
		$ftp48 = "503 Login with USER first."
		$ftp49 = "504 Command not implemented."
		$ftp50 = "504 Not implemented for this command."
		$ftp51 = "504 Server does not understand the specified protection level."
		$ftp52 = "510 EPRT IP is not same as client IP."
		$ftp53 = "510 EPRT is disabled."
		$ftp54 = "510 PORT IP mismatch."
		$ftp55 = "510 Port is disabled."
		$ftp56 = "510 Syntax error in parameters."
		$ftp57 = "510 Syntax error."
		$ftp58 = "530 Access denied."
		$ftp59 = "530 Anonymous connection is not allowed."
		$ftp60 = "530 Authentication failed."
		$ftp61 = "530 Invalid user name."
		$ftp62 = "550 Already exists."
		$ftp63 = "550 Cannot create directory."
		$ftp64 = "550 Cannot remove directory."
		$ftp65 = "550 File unavailable."
		$ftp66 = "550 Invalid path."
		$ftp67 = "550 No permission."
		$ftp68 = "550 No such directory."
		$ftp69 = "550 No such file or directory."
		$ftp70 = "550 Not a plain file."
		$ftp71 = "550 Not a valid directory."
		$ftp72 = "550 Not a valid file."
		$ftp73 = "550 Permission denied."
		$ftp74 = "550 Unique file name error."
		$ftp75 = "551 Error on input file."
		$ftp76 = "551 Error on output file."
		$ftp77 = "551 File listing failed."
		$ftp78 = "552 Invalid port number."
		$ftp79 = "552 Not a valid port number."
		$ftp80 = "553 Cannot rename file."
		$ftp81 = "553 Host unknown."
		$ftp82 = "553 No permission."
		$ftp83 = "553 Not a valid file name."
		$ftp84 = "Interactive mode on."
		$ftp85 = "bytes received in"
		$ftp86 = "command successful"

	condition:
		4 of them
}


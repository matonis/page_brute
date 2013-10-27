page_brute (beta!)
==========

**page_brute.py** is a digital forensic tool purposed to analyze Windows Page Files by appying YARA-based signatures to fix-sized blocks of pagefile.sys. 

***This tool can be used to:***
 * Disambiguate evidence within pagefile.sys by logically grouping blocks/pages into categories based on YARA rulesets.
 * Identify page files that contain remanants of popular cleartext protocols such as HTTP/FTP, etc to identify network activities.
 * Identify potential attacker activities based on popular command syntaxes used during internal propagations.
 * Identify evidence of active malware infections based on YARA signatures for known malware.
 * Isolate page files that contain signatures/magic values for popular file formats for more precise file carving.

##NOTICE:
This tool is currently in beta! This utility and its signature set is subject to change in the near future! For suggestions - email the author via github.

##Requires:
 * yara & yara-python: http://code.google.com/p/yara-project/downloads/list
 * default_signatures.yar (see above)

##How does it work?
1. Given block size, page_brute.py reads in pagefile in fixed-sized blocks (default, 4096 bytes)
2. For each block, page_brute decides if the block is null - if null, the block is skipped.
3. If block is not null, the block is applied against compiled yara signatures (defined in -r/--rules argument).
  * If -r/--rules not provided, page_brute.py will read from the default ruleset: default_signatures.yar
  * Custom rules stored in a folder can also be provided as an argument to -r/--rules (must end in .yar)
4. If a block matches a YARA signature, the raw block will be stored in the corresponding output directory.
  * -o/--scanname defines output folder that raw blocks will be saved.
  * If no output is specified, a default folder is created in pwd: PAGE_BRUTE-YYYY-MM-DD-HH:MM:SS-RESULTS
5. Blocks are labeled by their logical page ID beginning at 0.
  * To determine offset, multiply pageID by the page size.

***NOTE:*** if a page file matches against multiple signatures, the corresponding page file will be copied to each rule directory.

##How do I write signatures?
YARA is a powerful engine that allows you to match groups of strings,binary sequences,and regular expressions with user-defined boolean conditions against pretty much anything.

To learn more about writing YARA rules, please see the informative user guide here: http://yara-project.googlecode.com/files/YARA%20User%27s%20Manual%201.6.pdf

##Current Signatures:
  * FTP
  * HTTP requests/responses
  * IRC
  * Administrative/Hidden Share Abuse
  * Remote system syntaxes
  * HTML
  * Javascript
  * CMD Shell (this might suck)
  * SMTP Message Headers

##Usage:
From the help page:
```
usage: page_brute-BETA.py [-h] [-f FILE] [-p SIZE] [-o SCANNAME] [-i]
                          [-r RULEFILE]

Checks pages in pagefiles for YARA-based rule matches. Useful to identify
forensic artifacts within Windows-based page files and characterize blocks
based on regular expressions.

optional arguments:
  -h, --help            show this help message and exit
  -r RULEFILE, --rules RULEFILE
                        File/directory containing YARA signatures (must end
                        with .yar)

  -f FILE, --file FILE  Pagefile or any chunk/block-based binary file
  -p SIZE, --size SIZE  Size of chunk/block in bytes (Default 4096)
  -o SCANNAME, --scanname SCANNAME
                        Descriptor of the scan session - used for output
                        directory
  -i, --invert          Given scan options, match all blocks that DO NOT match
                        a ruleset
```
###In Action:
```
root@system:~/Desktop/page/page_brute# ./page_brute-BETA.py --file=pagefile.sys
[+] - PAGE_BRUTE processing file: pagefile.sys
[+] - Ruleset Compilation Successful.
[+] - PAGE_BRUTE running with the following options:
	[-] - FILE: pagefile.sys
	[-] - PAGE_SIZE: 4096
	[-] - RULES TYPE: DEFAULT
	[-] - RULE LOCATION: default_signatures.yar
	[-] - INVERSION SCAN: False
	[-] - WORKING DIR: PAGE_BRUTE-2013-10-27-01:09:33-RESULTS
	=================

        [!] FLAGGED BLOCK 56: cmdshell
        [!] FLAGGED BLOCK 87: cmdshell
        [!] FLAGGED BLOCK 1222: webartifact_html
        [!] FLAGGED BLOCK 1454: webartifact_html
        [!] FLAGGED BLOCK 1782: webartifact_html
        [!] FLAGGED BLOCK 2200: webartifact_html
        [!] FLAGGED BLOCK 3781: webartifact_html
        
root@system:~/Desktop/page/page_brute# ls -lR PAGE_BRUTE-2013-10-27-01\:09\:33-RESULTS/
PAGE_BRUTE-2013-10-27-01:09:33-RESULTS/:
total 8
drwxr-xr-x 2 root root 4096 Oct 27 01:09 cmdshell
drwxr-xr-x 2 root root 4096 Oct 27 01:09 webartifact_html

PAGE_BRUTE-2013-10-27-01:09:33-RESULTS/cmdshell:
total 8
-rw-r--r-- 1 root root 4096 Oct 27 01:09 118.page
-rw-r--r-- 1 root root 4096 Oct 27 01:09 77.page

PAGE_BRUTE-2013-10-27-01:09:33-RESULTS/webartifact_html:
total 20
-rw-r--r-- 1 root root 4096 Oct 27 01:09 1330.page
-rw-r--r-- 1 root root 4096 Oct 27 01:09 1445.page

root@system:~/Desktop/page/page_brute/PAGE_BRUTE-2013-10-27-01:20:28-RESULTS/webartifact_html# xxd 24606.page 
0000000: 613e 3c2f 7464 3e0d 0a20 2020 2020 2020  a></td>..       
0000010: 2020 203c 2f74 723e 0d0a 0d0a 2020 2020     </tr>....    
0000020: 2020 2020 2020 3c74 7220 6964 3d22 446f        <tr id="Do
0000030: 4f76 6572 7269 6465 2220 7374 796c 653d  Override" style=
0000040: 2264 6973 706c 6179 3d27 6e6f 6e65 2722  "display='none'"
0000050: 3e20 0d0a 2020 2020 2020 2020 2020 2020  > ..            
0000060: 3c74 643e 3c69 6d67 2069 643d 226e 6f74  <td><img id="not
0000070: 5265 636f 6d6d 656e 6465 6449 636f 6e22  RecommendedIcon"
0000080: 2073 7263 3d22 7265 645f 7368 6965 6c64   src="red_shield
0000090: 2e70 6e67 2220 626f 7264 6572 3d22 3022  .png" border="0"
00000a0: 2061 6c74 3d22 4e6f 7420 7265 636f 6d6d   alt="Not recomm
00000b0: 656e 6465 6420 6963 6f6e 2220 636c 6173  ended icon" clas
00000c0: 733d 2261 6374 696f 6e49 636f 6e22 3e3c  s="actionIcon"><
00000d0: 2f74 643e 0d0a 2020 2020 2020 2020 2020  /td>..          
00000e0: 2020 3c74 6420 7374 796c 653d 2270 6164    <td style="pad
00000f0: 6469 6e67 2d62 6f74 746f 6d3a 202e 3165  ding-bottom: .1e


```

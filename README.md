page_brute
==========

**page_brute.py** is a digital forensic tool purposed to analyze Windows Page Files by appying YARA-based signatures to fix-sized blocks of pagefile.sys. 

***This tool can be used to:***
 * Disambiguate evidence within pagefile.sys by logically grouping blocks/pages into categories based on YARA rulesets.
 * Identify page files that contain remanants of popular cleartext protocols such as HTTP/FTP, etc to identify network activities.
 * Identify potential attacker activities based on popular command syntaxes used during internal propagations.
 * Isolate page files that contain signatures/magic values for popular file formats for more precise file carving.

##NOTICE:
This tool is currently in beta! This utility and its signature set is subject to change in the near future! For suggestions - email the author @ dfir.matonis@gmail.com.

##Requires:
 * yara & yara-python: http://code.google.com/p/yara-project/downloads/list

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

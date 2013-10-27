page_brute
==========

page_brute.py is a digital forensic tool used to analyze Windows Page Files by appying YARA-based signatures to fix-sized blocks of pagefile.sys. 

***This tool can be used to:***
 * Disambiguate evidence within pagefile.sys by logically grouping blocks/pages into categories based on YARA rulesets.
 * Identify page files that contain remanants of popular protocols such as HTTP/FTP, etc to identify network activities.
 * Identify potential attacker activities based on popular command syntaxes used during internal propagations.
 * Isolate page files that contain headers for popular file formats for more precise file carving.

* Requires:
yara & yara-python: http://code.google.com/p/yara-project/downloads/list


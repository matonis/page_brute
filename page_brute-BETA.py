#!/usr/bin/python
#
#	page_brute.py
#	by @matonis - secualexploits.blogspot.com - www.mike-matonis.com
#	Summer of 2013
#


import sys
import argparse
import datetime
import glob
import os
import os.path
import binascii

try:
        import yara
except:
        print "[!] - ERROR: Could not import YARA..."
        print "...did you install yara and yara-python? Exiting."
        sys.exit()


def is_block_null(block):
	#Here we test to see if the block is null..if so, skip.
	RAW_BLOCK=binascii.hexlify(block)
	NULL_REF=binascii.hexlify(NULL_REFERENCE)
	if RAW_BLOCK == NULL_REF:
		return True
	else:
		return False

def build_ruleset():
	if RULETYPE == "FILE":
		try:
			rules=yara.compile(str(RULES))
			print "..... Ruleset Compilation Successful."
			return rules
		except:
			print "[!] - Could not compile YARA rule: %s" % RULES
			print "Exiting."
			sys.exit()
	
	elif RULETYPE == "FOLDER":
		RULEDATA=""
		#::Get list of files ending in .yara
		
		RULE_COUNT = len(glob.glob1(RULES,"*.yar"))
		if RULE_COUNT != 0:
			for yara_file in glob.glob(os.path.join(RULES, "*.yar")):
				try:
					yara.compile(str(yara_file))
					print "..... Syntax appears to be OK: %s " % yara_file
					try:
						with open(yara_file, "r") as sig_file:
							file_contents=sig_file.read()
							RULEDATA=RULEDATA + "\n" + file_contents
					except:
						print "..... SKIPPING: Could not open file for reading: %s " % yara_file
				except:
					print "..... SKIPPING: Could not compile rule: %s " % yara_file
			try:
				rules=yara.compile(source=RULEDATA)
				print "..... SUCCESS! Compiled noted yara rulesets.\n"
				return rules
			except:
				print "[!] - Some catastropic error occurred in the compilation of signatureswithin the directory. Exiting."
				sys.exit()
		else:
			print "No files ending in .yar within: %s " % RULES
			print "Exiting."
			sys.exit()
	
	elif RULETYPE == "DEFAULT":
		rules=yara.compile(str(RULES))
		print "[+] - Ruleset Compilation Successful."
		return rules

	else:
		print "[!] - ERROR: Possible catastrophic error on build_ruleset. Exiting."
		sys.exit()

def print_procedures():
	print "[+] - PAGE_BRUTE running with the following options:"
	print "\t[-] - FILE: %s" % FILE
	print "\t[-] - PAGE_SIZE: %s" % PAGE_SIZE
	print "\t[-] - RULES TYPE: %s" % RULETYPE
	print "\t[-] - RULE LOCATION: %s" % RULES
	print "\t[-] - INVERSION SCAN: %s" % INVERT
	print "\t[-] - WORKING DIR: %s" % WORKING_DIR
	print "\t=================\n"

def main():

	global FILE
	global PAGE_SIZE
	global RULES
	global SCANNAME
	global INVERT
	global RULETYPE
	global NULL_REFERENCE

	argument_parser = argparse.ArgumentParser(description="Checks pages in pagefiles for YARA-based rule matches. Useful to identify forensic artifacts within Windows-based page files and characterize blocks based on regular expressions.")
	
	group_arg = argument_parser.add_argument_group()
	group_arg.add_argument("-f", "--file", metavar="FILE", help="Pagefile or any chunk/block-based binary file")
	group_arg.add_argument("-p", "--size", metavar="SIZE", help="Size of chunk/block in bytes (Default 4096)")
	group_arg.add_argument("-o", "--scanname", metavar="SCANNAME", help="Descriptor of the scan session - used for output directory")
	group_arg.add_argument("-i", "--invert", help="Given scan options, match all blocks that DO NOT match a ruleset",action='store_true')

	group_arg = argument_parser.add_mutually_exclusive_group()
	group_arg.add_argument("-r", "--rules", metavar="RULEFILE", help="File/directory containing YARA signatures (must end with .yar)")

	args = argument_parser.parse_args()

	if len(sys.argv) < 2:
		print argument_parser.print_help()
		sys.exit()

	#::Check to see if file was provided::#
	if args.file:
		try:
			with open(args.file):
				FILE=args.file
				print "[+] - PAGE_BRUTE processing file: %s" % FILE
		except:
			print "[!] - Could not open %s. Exiting." % FILE
			sys.exit()
	else:
		print "[!] - No file provided. Use -f, --file to provide a file. Exiting."
		sys.exit()

	#::Check to see if page size provided::#
	if args.size:
		PAGE_SIZE=int(args.size)
		NULL_REFERENCE= '\x00' * PAGE_SIZE
	else:
		PAGE_SIZE=4096
		NULL_REFERENCE= '\x00' * PAGE_SIZE

	#::Check if --scan-name provided::#
	if args.scanname:
		SCANNAME=args.scanname
	else:
		SCANNAME="PAGE_BRUTE-" + datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S") + "-RESULTS"
	
	#::Check if --invert-match provided::#
	if args.invert:
		INVERT=True
	else:
		INVERT=False
	
	#::Check if --rule-file provdided - if not, use default ruleset::#
	if args.rules:
		RULES=args.rules
		try:
			#::Is File?::#
			if os.path.isfile(RULES):
				RULETYPE="FILE"
				print "[+] - YARA rule of File type provided for compilation: %s" % RULES
			elif os.path.isdir(RULES):
				print "[+] - YARA rule of Folder type provided for compilation: %s" % RULES
				RULETYPE="FOLDER"
		except:
			print "[!] - Possible catastrophic error with the provided rule file...exiting."
			sys.exit()
	else:
		try:
			with open("default_signatures.yar"):
				RULES="default_signatures.yar"
				RULETYPE="DEFAULT"
		except:
			print "[!] - Could not locate \"default_signature.yar\". Find it or provide custom signatures via --rules. Exiting."
			sys.exit()
	
	#::Compile rules::#
	authoritative_rules=build_ruleset()
	#::Build directory structure
	global WORKING_DIR
	WORKING_DIR=SCANNAME
	if not os.path.exists(WORKING_DIR):
		os.makedirs(WORKING_DIR)
	#::Let People Know what we're doing::#
	print_procedures()	
	#::Find Evil::#
	page_id=0
	with open(FILE, "rb") as page_file:
		while True:
			matched=False
			raw_page=page_file.read(PAGE_SIZE)
			if raw_page == "":
				print "Done!"
				print "Ending page_id is: %s" % page_id
				break
			if not is_block_null(raw_page):
                                #::Determine if block is null...:
				for matches in authoritative_rules.match(data=raw_page):
					if INVERT == True:
						matched=True
					else:
						CHUNK_OUTPUT_DIR=WORKING_DIR + "/" + matches.rule
						print "        [!] FLAGGED BLOCK " + str(page_id) + ": " + matches.rule

						if not os.path.exists(CHUNK_OUTPUT_DIR):
							os.makedirs(CHUNK_OUTPUT_DIR)

                                       		#::Save chunk to file::#
						CHUNK_OUTPUT_FWD=CHUNK_OUTPUT_DIR + "/" + str(page_id) + ".page"
						page_export=open(CHUNK_OUTPUT_FWD,'w+')
						page_export.write(raw_page)
						page_export.close()

				if INVERT == True:
					if matched == False:
						CHUNK_OUTPUT_DIR=WORKING_DIR + "/INVERTED-MATCH"
						print "        [!] BLOCK DOES NOT MATCH ANY KNOWN SIGNATURE " + str(page_id)
						if not os.path.exists(CHUNK_OUTPUT_DIR):
							os.makedirs(CHUNK_OUTPUT_DIR)

						CHUNK_OUTPUT_FWD=CHUNK_OUTPUT_DIR + "/" + str(page_id) + ".page"
						page_export=open(CHUNK_OUTPUT_FWD,'w+')
						page_export.write(raw_page)
						page_export.close()
			#::Increment Counter for offset increment::#
			page_id=page_id+1

if __name__ == "__main__":
    main()

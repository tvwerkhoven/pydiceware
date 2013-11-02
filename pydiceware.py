#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@file pydiceware.py -- generate Diceware(r) passwords
@author Tim van Werkhoven
@date 20131031
@copyright Copyright (c) 2013 Tim van Werkhoven

Given a Diceware(r) compatible word list file, generate a password of 
certain number of words. When generating, verify the word list integrity and 
check that the password is ok.

From Gutenberg
==============
URL: https://en.wiktionary.org/wiki/Wiktionary:Frequency_lists/PG/2006/04/1-10000
regexp: [0-9]+[ 	]+([^ ]+)[ 	]+[0-9\.]+ --> \1

This file is licensed under the Creative Commons Attribution-Share Alike
license versions 3.0 or higher, see
http://creativecommons.org/licenses/by-sa/3.0/
"""

import math
import sys
import argparse
import os
import urllib
import warnings

AUTHOR = "Tim van Werkhoven (timvanwerkhoven@gmail.com)"
DATE = "20131031"
WORDLISTURLS = ["http://world.std.com/%7Ereinhold/diceware.wordlist.asc", 
"http://world.std.com/%7Ereinhold/beale.wordlist.asc"]

def main():
	(parser, args) = parsopts()

	if (args.fetch):
		for url in WORDLISTURLS:
			outfile = os.path.basename(url)
			if (args.verb): print "Fetching", outfile
			urllib.urlretrieve (url, outfile)
			read_wordlist(outfile, maxlength=args.maxlength, verb=1)
		return

	words = read_wordlist(args.wordlist, maxlength=args.maxlength, verb=args.verb)
	if (args.dry): return

	for i in range(args.c):
		passwords = make_password(words, nwords=args.n, verb=args.verb)
		print " ".join(passwords)

def parsopts():
	"""
	Parse program options and return results. This routine will take input 
	from sys.argv through parser.parse_args().

	@return Tuple of (parser, args), see argparse.ArgumentParser for details.
	"""

	parser = argparse.ArgumentParser(description='Generate Diceware(r) passwords', epilog='Comments & bugreports to %s' % (AUTHOR), prog='pydiceware')


	parser.add_argument('wordlist', nargs='?', default=None,
				help='Word list to use as input')
	parser.add_argument('-n', type=int, default=5,
				help='number of words (5)')
	parser.add_argument('-c', type=int, default=24,
				help='number of runs (24)')
	parser.add_argument('--maxlength', type=int, default=7,
				help='discard words longer than this (7)')

	parser.add_argument('--dry', action='store_true', default=False,
				help='dry run, only analyze wordlist (False)')
	parser.add_argument('--fetch', action='store_true', default=False,
				help='download lists to current directory (False)')

	parser.add_argument('-v', dest='debug', action='append_const', const=1,
				help='increase verbosity')
	parser.add_argument('-q', dest='debug', action='append_const', const=-1,
				help='decrease verbosity')

	args = parser.parse_args()

	args.verb = sum(args.debug) if (args.debug) else 0
	if (not args.fetch and not args.wordlist):
		parser.print_usage()
		sys.stderr.write(parser.prog + ": error: wordlist required without --fetch\n")
		sys.exit(1)

	return (parser, args)

def read_wordlist(filepath, maxlength, verb=0):
	"""
	Read word list from disk, either Diceware(r) compatible or a regular 
	list of words.
	"""

	try:
		wordlist = read_diceware_wordlist(filepath)
	except:
		wordlist = read_regular_wordlist(filepath)

	wordlist = check_wordlist(wordlist, maxlength=maxlength, verb=verb)

	return wordlist

def read_regular_wordlist(filepath, verb=0):
	"""
	Read regular word lit from disk, with one word per line.
	"""

	with open(filepath) as fd:
		data = fd.readlines()

	wordlist = [line.strip() for line in data]

	return wordlist

def read_diceware_wordlist(filepath, verb=0):
	"""
	Read Diceware(r) compatible wordlist from disk, return sanitized list of 
	words.
	"""
	with open(filepath) as fd:
		# Find first useful line, which should have dice outcome '11111'
		wordlist = fd.readlines()
		for c, l in enumerate(wordlist):
			if "11111" in l.strip():
				break
		wordlist = wordlist[c:c+6**5]

	# Check wordlist length
	assert len(wordlist) == 6**5, "Wordlist of unexpected length"
	assert wordlist[0][:5] == '11111', "Wordlist malformed"
	assert wordlist[-1][:5] == '66666', "Wordlist malformed"

	words = [w.split()[1] for w in wordlist]

	return words

def check_wordlist(wordlist, maxlength, verb=0):
	"""
	Check wordlist sanity, warn if corrupted.

	1. Limit maximum word length (to ensure we can remember it)
	2. Check for duplicates
	3. Check brute-force entropy of word list (i.e. the number of unique characters used, approximately weighted to their occurence)

	Additionally, print the entropy per word for the word list, print the 
	histogram of word lengths, print the entropy for each 
	"""
	# Filter out long words
	wordlist = [w for w in wordlist if len(w) <= maxlength]

	# Check wordlist uniqueness
	ndupe = len(wordlist) - len(frozenset(wordlist))
	assert ndupe < 10, "Found %d duplicate words" % ndupe
	if (verb):
		wordentr = math.log(len(wordlist), 2) 
		print "Got %d words (%.2g %.2g %.2g %.2g %.2g %.2g %.2g b/word)" % (len(wordlist), wordentr, 2*wordentr, 3*wordentr, 4*wordentr, 5*wordentr, 6*wordentr, 7*wordentr)

	# Check min, max and avg word length
	wlen = [len(w) for w in wordlist]
	wlens = frozenset(wlen)
	if max(wlens) > 10: warnings.warn("Maximum word length >= 10, difficult to remember")

	if (verb):
		print "Word length min: %g, max: %g, avg: %.3g" % (min(wlens), max(wlens), sum(wlen)*1./len(wlen))
		for l in wlens:
			print " Length %d, occurence: %d" % (l, wlen.count(l))

	# Check spread of characters through wordlist
	wordstr = "".join(wordlist)
	uniqchrs = frozenset(wordstr)
	chrcount = [wordstr.count(c) for c in uniqchrs]
	nchr = sum(c > sum(chrcount)*1./len(chrcount) for c in chrcount)
	if (verb):
		print "Character entropy: %d unique, %d ok (==%.2g bit/char)" % (len(uniqchrs), nchr, math.log(nchr,2))
	if (nchr<20): warnings.warn("Low character entropy: %g bit/char" % nchr)

	return wordlist

def make_password(words, nwords=5, nchr=20, verb=0):
	"""
	Given a word list, make a new password. If the Diceware(r) strength is 
	weaker than a brute-force attack, re-generate a password.
	"""
	assert nwords > 0
	MAXN = len(words) # should be 7776 == 6**5
	NBITS = int(math.log(MAXN,2)/8 + 1)

	passwords = []

	for i in range(nwords):
		# Make random number between [0, MAXN) by taking a random number from
		# the cryptographically secure source os.urandom(), then reject 
		# numbers outside the requested range. This ensures homogeneous 
		# spread through [0, MAXN)
		r=MAXN
		while (r>=MAXN):
			r = sum(ord(c)*256**i for i,c in enumerate(os.urandom(NBITS)))
		passwords.append(words[r])

	# Check entropy based on Diceware(r) password space
	entropy1 = nwords*math.log(MAXN, 2)
	# Check entropy based on character password space 
	entropy2 = len("".join(passwords))*math.log(nchr, 2)

	if (entropy2 < entropy1):
		warnings.warn("Low brute-force entropy, re-generating...")
		passwords = make_password(words, nwords, nchr, verb=0)

	return passwords

# Run main program, must be at end
if __name__ == "__main__":
	sys.exit(main())

# EOF

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

This file is licensed under the Creative Commons Attribution-Share Alike
license versions 3.0 or higher, see
http://creativecommons.org/licenses/by-sa/3.0/
"""

import math
import sys
import argparse
import os
import urllib

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
			read_wordlist(outfile, verb=1)
		return

	words = read_wordlist(args.wordlist, verb=args.verb)
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


	parser.add_argument('wordlist', nargs='*',
				help='Word list to use as input')
	parser.add_argument('-n', type=int, default=5,
				help='number of words (5)')
	parser.add_argument('-c', type=int, default=24,
				help='number of runs (24)')
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

	return (parser, args)

def read_wordlist(filepath, verb=0):
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

	# Check wordlist uniqueness
	words = [w.split()[1] for w in wordlist]
	ndupe = len(words) - len(frozenset(words))
	assert ndupe < 10, "Found %d duplicate words" % ndupe

	# Check min, max and avg word length
	wlen = [len(w) for w in words]
	wlens = frozenset(wlen)
	assert min(wlens) > 0, "Minimum word length <= 0"
	assert max(wlens) < 10, "Maximum word length > 10, difficult to remember"

	if (verb):
		print "Word length min, max, avg:", min(wlens), max(wlens), sum(wlen)*1./len(wlen)
		for l in wlens:
			print "Length, occurence:", l, wlen.count(l)

	# Check spread of characters through wordlist
	wordstr = "".join(words)
	uniqchrs = frozenset(wordstr)
	chrcount = [wordstr.count(c) for c in uniqchrs]
	nchr = sum(c > sum(chrcount)*1./len(chrcount) for c in chrcount)
	if (verb):
		print "Character entropy: %d unique, %d ok (==%.2g bit)" % (len(uniqchrs), nchr, math.log(nchr,2))
	assert nchr>=20, "Character entropy very low!"

	return words

def make_password(words, nwords=5, nchr=20, verb=0):
	"""
	Given a word list, make a new password
	"""
	assert nwords > 0
	MAXN = len(words) # should be 7776 == 6**5
	NBITS = int(math.log(MAXN,2)/8 + 1)

	passwords = []

	for i in range(nwords):
		# Make random number between [0, MAXN] by taking a random number from
		# the cryptographically secure source os.urandom(), then reject numbers 
		# outside the requested range. This ensures homogeneous spread through 
		# [0, MAXN]
		r=MAXN+1
		while (r>MAXN):
			r = sum(ord(c)*256**i for i,c in enumerate(os.urandom(NBITS)))
		# Choose word from list
		if (verb): print "got: ", words[r].strip()
		passwords.append(words[r])

	# Check entropy based on Diceware password space
	entropy1 = nwords*math.log(MAXN, 2)
	# Check entropy based on character password space 
	entropy2 = len("".join(passwords))*math.log(nchr, 2)

	if (entropy2 < entropy1):
		print "Password weak against brute force attack (%d bits vs %d bits)" % (entropy1, entropy2)
	elif (verb):
		print "Password entropy ok (%d bits vs %d bits)" % (entropy1, entropy2)

	return passwords

# Run main program, must be at end
if __name__ == "__main__":
	sys.exit(main())

# EOF

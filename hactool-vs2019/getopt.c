/* Getopt for Microsoft C
This code is a modification of the Free Software Foundation, Inc.
Getopt library for parsing command line argument the purpose was
to provide a Microsoft Visual C friendly derivative. This code
provides functionality for both Unicode and Multibyte builds.

Date: 02/03/2011 - Ludvik Jerabek - Initial Release
Version: 1.0
Comment: Supports getopt, getopt_long, and getopt_long_only
and POSIXLY_CORRECT environment flag
License: LGPL

Revisions:

09/04/2014 - bowen han get the latest getopt source

**DISCLAIMER**
Getopt for GNU.
   NOTE: getopt is part of the C library, so if you don't know what
   "Keep this file name-space clean" means, talk to drepper@gnu.org
   before changing it!
   Copyright (C) 1987-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
//#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>

# include <wchar.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>
#ifndef ELIDE_CODE

#ifndef attribute_hidden
# define attribute_hidden
#endif

/* This version of `getopt' appears to the caller like standard Unix `getopt'
   but it behaves differently for the user, since it allows the user
   to intersperse the options with the other arguments.

   As `getopt' works, it permutes the elements of ARGV so that,
   when it is done, all the options precede everything else.  Thus
   all application programs are extended to handle flexible argument order.

   Setting the environment variable POSIXLY_CORRECT disables permutation.
   Then the behavior is completely standard.

   GNU application programs can use a third alternative mode in which
   they can distinguish the relative order of options and other arguments.  */

#include "getopt.h"
#include "getopt_int.h"

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

TCHAR *optarg;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `optind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

/* 1003.2 says this must be 1 before any call.  */
int optind = 1;

/* Callers store zero here to inhibit the error message
   for unrecognized options.  */

int opterr = 1;

/* Set to an option character which was unrecognized.
   This must be initialized on some systems to avoid linking in the
   system's own getopt implementation.  */

int optopt = _T('?');

/* Keep a global copy of all internal members of getopt_data.  */

static struct _getopt_data getopt_data;


#ifndef __GNU_LIBRARY__



#endif /* not __GNU_LIBRARY__ */

#ifdef _LIBC
/* Stored original parameters.
   XXX This is no good solution.  We should rather copy the args so
   that we can compare them later.  But we must not use malloc(3).  */
extern int __libc_argc;
extern TCHAR **__libc_argv;

/* Bash 2.0 gives us an environment variable containing flags
   indicating ARGV elements that should not be considered arguments.  */

# ifdef USE_NONOPTION_FLAGS
/* Defined in getopt_init.c  */
extern TCHAR *__getopt_nonoption_flags;
# endif

# ifdef USE_NONOPTION_FLAGS
#  define SWAP_FLAGS(ch1, ch2) \
  if (d->__nonoption_flags_len > 0)					      \
    {									      \
      char __tmp = __getopt_nonoption_flags[ch1];			      \
      __getopt_nonoption_flags[ch1] = __getopt_nonoption_flags[ch2];	      \
      __getopt_nonoption_flags[ch2] = __tmp;				      \
    }
# else
#  define SWAP_FLAGS(ch1, ch2)
# endif
#else	/* !_LIBC */
# define SWAP_FLAGS(ch1, ch2)
#endif	/* _LIBC */

/* Exchange two adjacent subsequences of ARGV.
   One subsequence is elements [first_nonopt,last_nonopt)
   which contains all the non-options that have been skipped so far.
   The other is elements [last_nonopt,optind), which contains all
   the options processed since those non-options were skipped.

   `first_nonopt' and `last_nonopt' are relocated so that they describe
   the new indices of the non-options in ARGV after they are moved.  */

static void
exchange (TCHAR **argv, struct _getopt_data *d)
{
  int bottom = d->__first_nonopt;
  int middle = d->__last_nonopt;
  int top = d->optind;
  TCHAR *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

#if defined _LIBC && defined USE_NONOPTION_FLAGS
  /* First make sure the handling of the `__getopt_nonoption_flags'
     string can work normally.  Our top argument must be in the range
     of the string.  */
  if (d->__nonoption_flags_len > 0 && top >= d->__nonoption_flags_max_len)
    {
      /* We must extend the array.  The user plays games with us and
	 presents new arguments.  */
      TCHAR *new_str = malloc ((top + 1)*sizeof(TCHAR));
      if (new_str == NULL)
	d->__nonoption_flags_len = d->__nonoption_flags_max_len = 0;
      else
	{
	  memset (__mempcpy (new_str, __getopt_nonoption_flags,
			     d->__nonoption_flags_max_len),
		  '\0', top + 1 - d->__nonoption_flags_max_len);
	  d->__nonoption_flags_max_len = top + 1;
	  __getopt_nonoption_flags = new_str;
	}
    }
#endif

  while (top > middle && middle > bottom)
    {
      if (top - middle > middle - bottom)
	{
	  /* Bottom segment is the short one.  */
	  int len = middle - bottom;
	  int i;

	  /* Swap it with the top part of the top segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[top - (middle - bottom) + i];
	      argv[top - (middle - bottom) + i] = tem;
	      SWAP_FLAGS (bottom + i, top - (middle - bottom) + i);
	    }
	  /* Exclude the moved bottom segment from further swapping.  */
	  top -= len;
	}
      else
	{
	  /* Top segment is the short one.  */
	  int len = top - middle;
	  int i;

	  /* Swap it with the bottom part of the bottom segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[middle + i];
	      argv[middle + i] = tem;
	      SWAP_FLAGS (bottom + i, middle + i);
	    }
	  /* Exclude the moved top segment from further swapping.  */
	  bottom += len;
	}
    }

  /* Update records for the slots the non-options now occupy.  */

  d->__first_nonopt += (d->optind - d->__last_nonopt);
  d->__last_nonopt = d->optind;
}

/* Initialize the internal data when the first call is made.  */

static const TCHAR *
_getopt_initialize (int argc, TCHAR *const *argv, const TCHAR *optstring,
		    struct _getopt_data *d, int posixly_correct)
{
  /* Start processing options with ARGV-element 1 (since ARGV-element 0
     is the program name); the sequence of previously skipped
     non-option ARGV-elements is empty.  */

  d->__first_nonopt = d->__last_nonopt = d->optind;

  d->__nextchar = NULL;

  d->__posixly_correct = posixly_correct | !!getenv ("POSIXLY_CORRECT");

  /* Determine how to handle the ordering of options and nonoptions.  */

  if (optstring[0] == _T('-'))
    {
      d->__ordering = RETURN_IN_ORDER;
      ++optstring;
    }
  else if (optstring[0] == _T('+'))
    {
      d->__ordering = REQUIRE_ORDER;
      ++optstring;
    }
  else if (d->__posixly_correct)
    d->__ordering = REQUIRE_ORDER;
  else
    d->__ordering = PERMUTE;

#if defined _LIBC && defined USE_NONOPTION_FLAGS
  if (!d->__posixly_correct
      && argc == __libc_argc && argv == __libc_argv)
    {
      if (d->__nonoption_flags_max_len == 0)
	{
	  if (__getopt_nonoption_flags == NULL
	      || __getopt_nonoption_flags[0] == '\0')
	    d->__nonoption_flags_max_len = -1;
	  else
	    {
	      const TCHAR *orig_str = __getopt_nonoption_flags;
	      int len = d->__nonoption_flags_max_len = lstrlen (orig_str);
	      if (d->__nonoption_flags_max_len < argc)
		d->__nonoption_flags_max_len = argc;
	      __getopt_nonoption_flags =
			  (TCHAR *) malloc ((d->__nonoption_flags_max_len)*sizeof(TCHAR));
	      if (__getopt_nonoption_flags == NULL)
		d->__nonoption_flags_max_len = -1;
	      else
		memset (__mempcpy (__getopt_nonoption_flags, orig_str, len),
			'\0', d->__nonoption_flags_max_len - len);
	    }
	}
      d->__nonoption_flags_len = d->__nonoption_flags_max_len;
    }
  else
    d->__nonoption_flags_len = 0;
#endif

  return optstring;
}

/* Scan elements of ARGV (whose length is ARGC) for option characters
   given in OPTSTRING.

   If an element of ARGV starts with '-', and is not exactly "-" or "--",
   then it is an option element.  The characters of this element
   (aside from the initial '-') are option characters.  If `getopt'
   is called repeatedly, it returns successively each of the option characters
   from each of the option elements.

   If `getopt' finds another option character, it returns that character,
   updating `optind' and `nextchar' so that the next call to `getopt' can
   resume the scan with the following option character or ARGV-element.

   If there are no more option characters, `getopt' returns -1.
   Then `optind' is the index in ARGV of the first ARGV-element
   that is not an option.  (The ARGV-elements have been permuted
   so that those that are not options now come last.)

   OPTSTRING is a string containing the legitimate option characters.
   If an option character is seen that is not listed in OPTSTRING,
   return '?' after printing an error message.  If you set `opterr' to
   zero, the error message is suppressed but we still return '?'.

   If a char in OPTSTRING is followed by a colon, that means it wants an arg,
   so the following text in the same ARGV-element, or the text of the following
   ARGV-element, is returned in `optarg'.  Two colons mean an option that
   wants an optional arg; if there is text in the current ARGV-element,
   it is returned in `optarg', otherwise `optarg' is set to zero.

   If OPTSTRING starts with `-' or `+', it requests different methods of
   handling the non-option ARGV-elements.
   See the comments about RETURN_IN_ORDER and REQUIRE_ORDER, above.

   Long-named options begin with `--' instead of `-'.
   Their names may be abbreviated as long as the abbreviation is unique
   or is an exact match for some defined option.  If they have an
   argument, it follows the option name in the same ARGV-element, separated
   from the option name by a `=', or else the in next ARGV-element.
   When `getopt' finds a long-named option, it returns 0 if that option's
   `flag' field is nonzero, the value of the option's `val' field
   if the `flag' field is zero.

   The elements of ARGV aren't really const, because we permute them.
   But we pretend they're const in the prototype to be compatible
   with other systems.

   LONGOPTS is a vector of `struct option' terminated by an
   element containing a name which is zero.

   LONGIND returns the index in LONGOPT of the long-named option found.
   It is only valid when a long-named option has been found by the most
   recent call.

   If LONG_ONLY is nonzero, '-' as well as '--' can introduce
   long-named options.  */

int
_getopt_internal_r (int argc, TCHAR *const *argv, const TCHAR *optstring,
		    const struct option *longopts, int *longind,
		    int long_only, struct _getopt_data *d, int posixly_correct)
{
  int print_errors = d->opterr;

  if (argc < 1)
    return -1;

  d->optarg = NULL;

  if (d->optind == 0 || !d->__initialized)
    {
      if (d->optind == 0)
	d->optind = 1;	/* Don't scan ARGV[0], the program name.  */
      optstring = _getopt_initialize (argc, argv, optstring, d,
				      posixly_correct);
      d->__initialized = 1;
    }
  else if (optstring[0] == _T('-') || optstring[0] == _T('+'))
    optstring++;
  if (optstring[0] == _T(':'))
    print_errors = 0;

  /* Test whether ARGV[optind] points to a non-option argument.
     Either it does not have option syntax, or there is an environment flag
     from the shell indicating it is not an option.  The later information
     is only used when the used in the GNU libc.  */

# define NONOPTION_P (argv[d->optind][0] != _T('-') || argv[d->optind][1] == _T('\0'))


  if (d->__nextchar == NULL || *d->__nextchar == _T('\0'))
    {
      /* Advance to the next ARGV-element.  */

      /* Give FIRST_NONOPT & LAST_NONOPT rational values if OPTIND has been
	 moved back by the user (who may also have changed the arguments).  */
      if (d->__last_nonopt > d->optind)
	d->__last_nonopt = d->optind;
      if (d->__first_nonopt > d->optind)
	d->__first_nonopt = d->optind;

      if (d->__ordering == PERMUTE)
	{
	  /* If we have just processed some options following some non-options,
	     exchange them so that the options come first.  */

	  if (d->__first_nonopt != d->__last_nonopt
	      && d->__last_nonopt != d->optind)
	    exchange ((TCHAR **) argv, d);
	  else if (d->__last_nonopt != d->optind)
	    d->__first_nonopt = d->optind;

	  /* Skip any additional non-options
	     and extend the range of non-options previously skipped.  */

	  while (d->optind < argc && NONOPTION_P)
	    d->optind++;
	  d->__last_nonopt = d->optind;
	}

      /* The special ARGV-element `--' means premature end of options.
	 Skip it like a null option,
	 then exchange with previous non-options as if it were an option,
	 then skip everything else like a non-option.  */

      if (d->optind != argc && !lstrcmp (argv[d->optind], _T("--")))
	{
	  d->optind++;

	  if (d->__first_nonopt != d->__last_nonopt
	      && d->__last_nonopt != d->optind)
	    exchange ((TCHAR **) argv, d);
	  else if (d->__first_nonopt == d->__last_nonopt)
	    d->__first_nonopt = d->optind;
	  d->__last_nonopt = argc;

	  d->optind = argc;
	}

      /* If we have done all the ARGV-elements, stop the scan
	 and back over any non-options that we skipped and permuted.  */

      if (d->optind == argc)
	{
	  /* Set the next-arg-index to point at the non-options
	     that we previously skipped, so the caller will digest them.  */
	  if (d->__first_nonopt != d->__last_nonopt)
	    d->optind = d->__first_nonopt;
	  return -1;
	}

      /* If we have come to a non-option and did not permute it,
	 either stop the scan or describe it to the caller and pass it by.  */

      if (NONOPTION_P)
	{
	  if (d->__ordering == REQUIRE_ORDER)
	    return -1;
	  d->optarg = argv[d->optind++];
	  return 1;
	}

      /* We have found another option-ARGV-element.
	 Skip the initial punctuation.  */

      d->__nextchar = (argv[d->optind] + 1
		  + (longopts != NULL && argv[d->optind][1] == _T('-')));
    }

  /* Decode the current option-ARGV-element.  */

  /* Check whether the ARGV-element is a long option.

     If long_only and the ARGV-element has the form "-f", where f is
     a valid short option, don't consider it an abbreviated form of
     a long option that starts with f.  Otherwise there would be no
     way to give the -f short option.

     On the other hand, if there's a long option "fubar" and
     the ARGV-element is "-fu", do consider that an abbreviation of
     the long option, just like "--fu", and not "-f" with arg "u".

     This distinction seems to be the most useful approach.  */

  if (longopts != NULL
	  && (argv[d->optind][1] == _T('-')
	  || (long_only && (argv[d->optind][2]
			    || !_tcschr (optstring, argv[d->optind][1])))))
    {
      TCHAR *nameend;
      unsigned int namelen;
      const struct option *p;
      const struct option *pfound = NULL;
      struct option_list
      {
	const struct option *p;
	struct option_list *next;
      } *ambig_list = NULL;
      int exact = 0;
      int indfound = -1;
      int option_index;

	  for (nameend = d->__nextchar; *nameend && *nameend != _T('='); nameend++)
	/* Do nothing.  */ ;
      namelen = (unsigned int)(nameend - d->__nextchar);

      /* Test all long options for either exact match
	 or abbreviated matches.  */
      for (p = longopts, option_index = 0; p->name; p++, option_index++)
	if (!_tcsnccmp (p->name, d->__nextchar, namelen))
	  {
	    if (namelen == (unsigned int) lstrlen (p->name))
	      {
		/* Exact match found.  */
		pfound = p;
		indfound = option_index;
		exact = 1;
		break;
	      }
	    else if (pfound == NULL)
	      {
		/* First nonexact match found.  */
		pfound = p;
		indfound = option_index;
	      }
	    else if (long_only
		     || pfound->has_arg != p->has_arg
		     || pfound->flag != p->flag
		     || pfound->val != p->val)
	      {
		/* Second or later nonexact match found.  */
		struct option_list *newp = _alloca (sizeof (*newp));
		newp->p = p;
		newp->next = ambig_list;
		ambig_list = newp;
	      }
	  }

      if (ambig_list != NULL && !exact)
	{
	  if (print_errors)
	    {
	      struct option_list first;
	      first.p = pfound;
	      first.next = ambig_list;
	      ambig_list = &first;

#if defined _LIBC
	      TCHAR *buf = NULL;
	      size_t buflen = 0;

	      FILE *fp = open_memstream (&buf, &buflen);
	      if (fp != NULL)
		{
		  _ftprintf (fp,
			   _T("%s: option '%s' is ambiguous; possibilities:"),
			   argv[0], argv[d->optind]);

		  do
		    {
		      _ftprintf (fp, " '--%s'", ambig_list->p->name);
		      ambig_list = ambig_list->next;
		    }
		  while (ambig_list != NULL);

		  fputc_unlocked ('\n', fp);

		  if (__builtin_expect (fclose (fp) != EOF, 1))
		    {
		      _IO_flockfile (stderr);

		      int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
		      ((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

		      __fxprintf (NULL, "%s", buf);

		      ((_IO_FILE *) stderr)->_flags2 = old_flags2;
		      _IO_funlockfile (stderr);

		      free (buf);
		    }
		}
#else
	      _ftprintf (stderr,
		       _T("%s: option '%s' is ambiguous; possibilities:"),
		       argv[0], argv[d->optind]);
	      do
		{
		  _ftprintf (stderr, _T(" '--%s'"), ambig_list->p->name);
		  ambig_list = ambig_list->next;
		}
	      while (ambig_list != NULL);

		fputc(_T('\n'), stderr);
#endif
	    }
	  d->__nextchar += lstrlen (d->__nextchar);
	  d->optind++;
	  d->optopt = 0;
	  return _T('?');
	}

      if (pfound != NULL)
	{
	  option_index = indfound;
	  d->optind++;
	  if (*nameend)
	    {
	      /* Don't test has_arg with >, because some C compilers don't
		 allow it to be used on enums.  */
	      if (pfound->has_arg)
		d->optarg = nameend + 1;
	      else
		{
		  if (print_errors)
		    {
#if defined _LIBC
		      TCHAR *buf;
		      int n;
#endif

			  if (argv[d->optind - 1][1] == _T('-'))
			{
			  /* --option */
#if defined _LIBC
			  n = __asprintf (&buf, _T("\
%s: option '--%s' doesn't allow an argument\n"),
					  argv[0], pfound->name);
#else
			  _ftprintf (stderr, _T("\
%s: option '--%s' doesn't allow an argument\n"),
				   argv[0], pfound->name);
#endif
			}
		      else
			{
			  /* +option or -option */
#if defined _LIBC
			  n = __asprintf (&buf, _T("\
%s: option '%c%s' doesn't allow an argument\n"),
					  argv[0], argv[d->optind - 1][0],
					  pfound->name);
#else
			  _ftprintf (stderr, _T("\
%s: option '%c%s' doesn't allow an argument\n"),
				   argv[0], argv[d->optind - 1][0],
				   pfound->name);
#endif
			}

#if defined _LIBC
		      if (n >= 0)
			{
			  _IO_flockfile (stderr);

			  int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
			  ((_IO_FILE *) stderr)->_flags2
			    |= _IO_FLAGS2_NOTCANCEL;

			  __fxprintf (NULL, "%s", buf);

			  ((_IO_FILE *) stderr)->_flags2 = old_flags2;
			  _IO_funlockfile (stderr);

			  free (buf);
			}
#endif
		    }

		  d->__nextchar += lstrlen (d->__nextchar);

		  d->optopt = pfound->val;
		  return _T('?');
		}
	    }
	  else if (pfound->has_arg == 1)
	    {
	      if (d->optind < argc)
		d->optarg = argv[d->optind++];
	      else
		{
		  if (print_errors)
		    {
#if defined _LIBC
		      TCHAR *buf;

		      if (__asprintf (&buf, _T("\
%s: option '--%s' requires an argument\n"),
				      argv[0], pfound->name) >= 0)
			{
			  _IO_flockfile (stderr);

			  int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
			  ((_IO_FILE *) stderr)->_flags2
			    |= _IO_FLAGS2_NOTCANCEL;

			  __fxprintf (NULL, "%s", buf);

			  ((_IO_FILE *) stderr)->_flags2 = old_flags2;
			  _IO_funlockfile (stderr);

			  free (buf);
			}
#else
		      _ftprintf (stderr,
			       _T("%s: option '--%s' requires an argument\n"),
			       argv[0], pfound->name);
#endif
		    }
		  d->__nextchar += lstrlen (d->__nextchar);
		  d->optopt = pfound->val;
		  return optstring[0] == _T(':') ? _T(':') : _T('?');
		}
	    }
	  d->__nextchar += lstrlen (d->__nextchar);
	  if (longind != NULL)
	    *longind = option_index;
	  if (pfound->flag)
	    {
	      *(pfound->flag) = pfound->val;
	      return 0;
	    }
	  return pfound->val;
	}

      /* Can't find it as a long option.  If this is not getopt_long_only,
	 or the option starts with '--' or is not a valid short
	 option, then it's an error.
	 Otherwise interpret it as a short option.  */
	if (!long_only || argv[d->optind][1] == _T('-')
	  || _tcschr (optstring, *d->__nextchar) == NULL)
	{
	  if (print_errors)
	    {
#if defined _LIBC
	      TCHAR *buf;
	      int n;
#endif

		  if (argv[d->optind][1] == _T('-'))
		{
		  /* --option */
#if defined _LIBC
		  n = __asprintf (&buf, _T("%s: unrecognized option '--%s'\n"),
				  argv[0], d->__nextchar);
#else
		  _ftprintf (stderr, _T("%s: unrecognized option '--%s'\n"),
			   argv[0], d->__nextchar);
#endif
		}
	      else
		{
		  /* +option or -option */
#if defined _LIBC
		  n = __asprintf (&buf, _T("%s: unrecognized option '%c%s'\n"),
				  argv[0], argv[d->optind][0], d->__nextchar);
#else
		  _ftprintf (stderr, _T("%s: unrecognized option '%c%s'\n"),
			   argv[0], argv[d->optind][0], d->__nextchar);
#endif
		}

#if defined _LIBC
	      if (n >= 0)
		{
		  _IO_flockfile (stderr);

		  int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
		  ((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

		  __fxprintf (NULL, "%s", buf);

		  ((_IO_FILE *) stderr)->_flags2 = old_flags2;
		  _IO_funlockfile (stderr);

		  free (buf);
		}
#endif
	    }
	  d->__nextchar = (TCHAR *) _T("");
	  d->optind++;
	  d->optopt = 0;
	  return _T('?');
	}
    }

  /* Look at and handle the next short option-character.  */

  {
    TCHAR c = *d->__nextchar++;
    TCHAR *temp = _tcschr (optstring, c);

    /* Increment `optind' when we start to process its last character.  */
	if (*d->__nextchar == _T('\0'))
      ++d->optind;

    if (temp == NULL || c == _T(':') || c == _T(';'))
      {
	if (print_errors)
	  {
#if defined _LIBC
	    TCHAR *buf;
	    int n;
#endif

#if defined _LIBC
	    n = __asprintf (&buf, _T("%s: invalid option -- '%c'\n"),
			    argv[0], c);
#else
	    _ftprintf (stderr, _T("%s: invalid option -- '%c'\n"), argv[0], c);
#endif

#if defined _LIBC
	    if (n >= 0)
	      {
		_IO_flockfile (stderr);

		int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
		((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

		__fxprintf (NULL, "%s", buf);

		((_IO_FILE *) stderr)->_flags2 = old_flags2;
		_IO_funlockfile (stderr);

		free (buf);
	      }
#endif
	  }
	d->optopt = c;
	return _T('?');
      }
    /* Convenience. Treat POSIX -W foo same as long option --foo */
	if (temp[0] == _T('W') && temp[1] == _T(';'))
      {
	if (longopts == NULL)
	  goto no_longs;

	TCHAR *nameend;
	const struct option *p;
	const struct option *pfound = NULL;
	int exact = 0;
	int ambig = 0;
	int indfound = 0;
	int option_index;

	/* This is an option that requires an argument.  */
	if (*d->__nextchar != _T('\0'))
	  {
	    d->optarg = d->__nextchar;
	    /* If we end this ARGV-element by taking the rest as an arg,
	       we must advance to the next element now.  */
	    d->optind++;
	  }
	else if (d->optind == argc)
	  {
	    if (print_errors)
	      {
#if defined _LIBC
		TCHAR *buf;

		if (__asprintf (&buf,
				_T("%s: option requires an argument -- '%c'\n"),
				argv[0], c) >= 0)
		  {
		    _IO_flockfile (stderr);

		    int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
		    ((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

		    __fxprintf (NULL, "%s", buf);

		    ((_IO_FILE *) stderr)->_flags2 = old_flags2;
		    _IO_funlockfile (stderr);

		    free (buf);
		  }
#else
		_ftprintf (stderr,
			 _T("%s: option requires an argument -- '%c'\n"),
			 argv[0], c);
#endif
	      }
	    d->optopt = c;
		if (optstring[0] == _T(':'))
			c = _T(':');
	    else
			c = _T('?');
	    return c;
	  }
	else
	  /* We already incremented `d->optind' once;
	     increment it again when taking next ARGV-elt as argument.  */
	  d->optarg = argv[d->optind++];

	/* optarg is now the argument, see if it's in the
	   table of longopts.  */

	for (d->__nextchar = nameend = d->optarg; *nameend && *nameend != _T('=');
	     nameend++)
	  /* Do nothing.  */ ;

	/* Test all long options for either exact match
	   or abbreviated matches.  */
	for (p = longopts, option_index = 0; p->name; p++, option_index++)
	  if (!_tcsnccmp (p->name, d->__nextchar, nameend - d->__nextchar))
	    {
	      if ((unsigned int) (nameend - d->__nextchar) == lstrlen (p->name))
		{
		  /* Exact match found.  */
		  pfound = p;
		  indfound = option_index;
		  exact = 1;
		  break;
		}
	      else if (pfound == NULL)
		{
		  /* First nonexact match found.  */
		  pfound = p;
		  indfound = option_index;
		}
	      else if (long_only
		       || pfound->has_arg != p->has_arg
		       || pfound->flag != p->flag
		       || pfound->val != p->val)
		/* Second or later nonexact match found.  */
		ambig = 1;
	    }
	if (ambig && !exact)
	  {
	    if (print_errors)
	      {
#if defined _LIBC
		TCHAR *buf;

		if (__asprintf (&buf, _T("%s: option '-W %s' is ambiguous\n"),
				argv[0], d->optarg) >= 0)
		  {
		    _IO_flockfile (stderr);

		    int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
		    ((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

		    __fxprintf (NULL, "%s", buf);

		    ((_IO_FILE *) stderr)->_flags2 = old_flags2;
		    _IO_funlockfile (stderr);

		    free (buf);
		  }
#else
		_ftprintf (stderr, _T("%s: option '-W %s' is ambiguous\n"),
			 argv[0], d->optarg);
#endif
	      }
	    d->__nextchar += lstrlen (d->__nextchar);
	    d->optind++;
		return _T('?');
	  }
	if (pfound != NULL)
	  {
	    option_index = indfound;
	    if (*nameend)
	      {
		/* Don't test has_arg with >, because some C compilers don't
		   allow it to be used on enums.  */
		if (pfound->has_arg)
		  d->optarg = nameend + 1;
		else
		  {
		    if (print_errors)
		      {
#if defined _LIBC
			TCHAR *buf;

			if (__asprintf (&buf, _T("\
%s: option '-W %s' doesn't allow an argument\n"),
					argv[0], pfound->name) >= 0)
			  {
			    _IO_flockfile (stderr);

			    int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
			    ((_IO_FILE *) stderr)->_flags2
			      |= _IO_FLAGS2_NOTCANCEL;

			    __fxprintf (NULL, "%s", buf);

			    ((_IO_FILE *) stderr)->_flags2 = old_flags2;
			    _IO_funlockfile (stderr);

			    free (buf);
			  }
#else
			_ftprintf (stderr, _T("\
%s: option '-W %s' doesn't allow an argument\n"),
				 argv[0], pfound->name);
#endif
		      }

		    d->__nextchar += lstrlen (d->__nextchar);
			return _T('?');
		  }
	      }
	    else if (pfound->has_arg == 1)
	      {
		if (d->optind < argc)
		  d->optarg = argv[d->optind++];
		else
		  {
		    if (print_errors)
		      {
#if defined _LIBC
			TCHAR *buf;

			if (__asprintf (&buf, _T("\
%s: option '-W %s' requires an argument\n"),
					argv[0], pfound->name) >= 0)
			  {
			    _IO_flockfile (stderr);

			    int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
			    ((_IO_FILE *) stderr)->_flags2
			      |= _IO_FLAGS2_NOTCANCEL;

			    __fxprintf (NULL, "%s", buf);

			    ((_IO_FILE *) stderr)->_flags2 = old_flags2;
			    _IO_funlockfile (stderr);

			    free (buf);
			  }
#else
			_ftprintf (stderr, _T("\
%s: option '-W %s' requires an argument\n"),
				 argv[0], pfound->name);
#endif
		      }
		    d->__nextchar += lstrlen (d->__nextchar);
			return optstring[0] == _T(':') ? _T(':') : _T('?');
		  }
	      }
	    else
	      d->optarg = NULL;
	    d->__nextchar += lstrlen (d->__nextchar);
	    if (longind != NULL)
	      *longind = option_index;
	    if (pfound->flag)
	      {
		*(pfound->flag) = pfound->val;
		return 0;
	      }
	    return pfound->val;
	  }

      no_longs:
	d->__nextchar = NULL;
	return _T('W');	/* Let the application handle it.   */
      }
	  if (temp[1] == _T(':'))
      {
		  if (temp[2] == _T(':'))
	  {
	    /* This is an option that accepts an argument optionally.  */
			  if (*d->__nextchar != _T('\0'))
	      {
		d->optarg = d->__nextchar;
		d->optind++;
	      }
	    else
	      d->optarg = NULL;
	    d->__nextchar = NULL;
	  }
	else
	  {
	    /* This is an option that requires an argument.  */
		if (*d->__nextchar != _T('\0'))
	      {
		d->optarg = d->__nextchar;
		/* If we end this ARGV-element by taking the rest as an arg,
		   we must advance to the next element now.  */
		d->optind++;
	      }
	    else if (d->optind == argc)
	      {
		if (print_errors)
		  {
#if defined _LIBC
		    TCHAR *buf;

		    if (__asprintf (&buf, _T("\
%s: option requires an argument -- '%c'\n"),
				    argv[0], c) >= 0)
		      {
			_IO_flockfile (stderr);

			int old_flags2 = ((_IO_FILE *) stderr)->_flags2;
			((_IO_FILE *) stderr)->_flags2 |= _IO_FLAGS2_NOTCANCEL;

			__fxprintf (NULL, "%s", buf);

			((_IO_FILE *) stderr)->_flags2 = old_flags2;
			_IO_funlockfile (stderr);

			free (buf);
		      }
#else
		    _ftprintf (stderr,
			     _T("%s: option requires an argument -- '%c'\n"),
			     argv[0], c);
#endif
		  }
		d->optopt = c;
		if (optstring[0] == _T(':'))
			c = _T(':');
		else
			c = _T('?');
	      }
	    else
	      /* We already incremented `optind' once;
		 increment it again when taking next ARGV-elt as argument.  */
	      d->optarg = argv[d->optind++];
	    d->__nextchar = NULL;
	  }
      }
    return c;
  }
}

int
_getopt_internal (int argc, TCHAR *const *argv, const TCHAR *optstring,
		  const struct option *longopts, int *longind, int long_only,
		  int posixly_correct)
{
  int result;

  getopt_data.optind = optind;
  getopt_data.opterr = opterr;

  result = _getopt_internal_r (argc, argv, optstring, longopts,
			       longind, long_only, &getopt_data,
			       posixly_correct);

  optind = getopt_data.optind;
  optarg = getopt_data.optarg;
  optopt = getopt_data.optopt;

  return result;
}

int
getopt (int argc, TCHAR *const *argv, const TCHAR *optstring)
{
  return _getopt_internal (argc, argv, optstring,
			   (const struct option *) 0,
			   (int *) 0,
			   0, 0);
}





int
getopt_long (int argc, TCHAR *const *argv, const TCHAR *options,
             const struct option *long_options, int *opt_index)
{
  return _getopt_internal (argc, (TCHAR **) argv, options, long_options,
                           opt_index, 0, 0);
}



/* Like getopt_long, but '-' as well as '--' can indicate a long option.
   If an option that starts with '-' (not '--') doesn't match a long option,
   but does match a short option, it is parsed as a short option
   instead.  */

int
getopt_long_only (int argc, TCHAR *const *argv,
                  const TCHAR *options,
                  const struct option *long_options, int *opt_index)
{
  return _getopt_internal (argc, (TCHAR **) argv, options, long_options,
                           opt_index, 1, 0);
}

int
_getopt_long_r(int argc, TCHAR* const* argv, const TCHAR* options,
	const struct option* long_options, int* opt_index,
	struct _getopt_data* d)
{
	return _getopt_internal_r(argc, argv, options, long_options, opt_index,
		0, d, 0);
}

int
_getopt_long_only_r (int argc, TCHAR* const* argv, const TCHAR *options,
                     const struct option *long_options, int *opt_index,
                     struct _getopt_data *d)
{
  return _getopt_internal_r (argc, argv, options, long_options, opt_index,
                             1, d, 0);
}










#ifdef _LIBC
int
__posix_getopt (int argc, TCHAR *const *argv, const TCHAR *optstring)
{
  return _getopt_internal (argc, argv, optstring,
			   (const struct option *) 0,
			   (int *) 0,
			   0, 1);
}
#endif

#endif	/* Not ELIDE_CODE.  */



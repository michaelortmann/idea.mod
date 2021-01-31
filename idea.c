/*
 * idea.c -- part of idea.mod
 *   encryption and decryption of passwords
 *
 */
/*
 * Copyright (C) 1997 Robey Pointer
 * Copyright (C) 1999, 2000, 2001, 2002 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
/*
 * This code was originally in the public domain.
 */
/*
 * Modified to run on Eggdrop 1.8.x and fixed some compile warnings
 *                                     -- pseudo@egg6.net (Sep 2010)
 */

#define MODULE_NAME "encryption"
#define MAKING_ENCRYPTION

#include "src/mod/module.h"
/*
#include "../../md5/md5c.c"
#include "../../md5/md5.h"
*/
typedef unsigned long MD5_u32plus;

typedef struct {
    MD5_u32plus lo, hi;
    MD5_u32plus a, b, c, d;
    unsigned char buffer[64];
    MD5_u32plus block[16];
} MD5_CTX;

#undef MD5_Init
#define MD5_Init ((void (*)(MD5_CTX *))global[277])
#undef global
static Function *global = NULL;
/********************************************/

/*
 *	idea.c - C source code for IDEA block cipher.
 *	IDEA (International Data Encryption Algorithm), formerly known as 
 *	IPES (Improved Proposed Encryption Standard).
 *	Algorithm developed by Xuejia Lai and James L. Massey, of ETH Zurich.
 *	This implementation modified and derived from original C code 
 *	developed by Xuejia Lai.  
 *	Zero-based indexing added, names changed from IPES to IDEA.
 *	CFB functions added.  Random number routines added.
 *
 *  Optimized for speed 21 Oct 92 by Colin Plumb.
 *  Very minor speedup on 23 Feb 93 by Colin Plumb.
 *  idearand() given a separate expanded key on 25 Feb 93, Colin Plumb.
 *  Totally restructured to eliminate static variables, 1 Aug 1993, Colin Plumb
 *
 *  (You know, I can't find any code in here that I haven't written.
 *  A few comments seem to be original, particularly the legalese
 *  below, but I don't think the authors mind having that reproduced.
 *  Thus, I hereby place this work in the public domain.  -Colin)
 *
 *	There are two adjustments that can be made to this code to
 *	speed it up.  Defaults may be used for PCs.  Only the -DIDEA32
 *	pays off significantly if selectively set or not set.
 *	Experiment to see what works best for your machine.
 *
 *	Multiplication: default is inline, -DAVOID_JUMPS uses a
 *		different version that does not do any conditional
 *		jumps (a few percent worse on a SPARC), while
 *		-DSMALL_CACHE takes it out of line to stay
 *		within a small on-chip code cache.
 *	Variables: normally, 16-bit variables are used, but some
 *		machines (notably RISCs) do not have 16-bit registers,
 *		so they do a great deal of masking.  -DIDEA32 uses "int"
 *		register variables and masks explicitly only where
 *		necessary.  On a SPARC, for example, this boosts
 *		performace by 30%.
 *
 *	The IDEA(tm) block cipher is covered by a patent held by ETH and a
 *	Swiss company called Ascom-Tech AG.  The Swiss patent number is
 *	PCT/CH91/00117.  International patents are pending. IDEA(tm) is a
 *	trademark of Ascom-Tech AG.  There is no license fee required for
 *	noncommercial use.  Commercial users may obtain licensing details
 *	from Dieter Profos, Ascom Tech AG, Solothurn Lab, Postfach 151, 4502
 *	Solothurn, Switzerland, Tel +41 65 242885, Fax +41 65 235761.
 *
 *	The IDEA block cipher uses a 64-bit block size, and a 128-bit key 
 *	size.  It breaks the 64-bit cipher block into four 16-bit words
 *	because all of the primitive inner operations are done with 16-bit 
 *	arithmetic.  It likewise breaks the 128-bit cipher key into eight 
 *	16-bit words.
 *
 *	For further information on the IDEA cipher, see these papers:
 *	1) Xuejia Lai, "Detailed Description and a Software Implementation of 
 *  	   the IPES Cipher", Institute for Signal and Information
 *   	   Processing, ETH-Zentrum, Zurich, Switzerland, 1991
 *	2) Xuejia Lai, James L. Massey, Sean Murphy, "Markov Ciphers and 
 *   	   Differential Cryptanalysis", Advances in Cryptology- EUROCRYPT'91
 *
 *	This code runs on arrays of bytes by taking pairs in big-endian
 *	order to make the 16-bit words that IDEA uses internally.  This
 *	produces the same result regardless of the byte order of the
 *	native CPU.
 */

#include "idea.h"

#ifdef IDEA32	/* Use >16-bit temporaries */
#define low16(x) ((x) & 0xFFFF)
typedef unsigned int uint16;	/* at LEAST 16 bits, maybe more */
#else
#define low16(x) (x)	/* this is only ever applied to uint16's */
typedef word16 uint16;
#endif

/*
 *	Multiplication, modulo (2**16)+1
 * Note that this code is structured on the assumption that
 * untaken branches are cheaper than taken branches, and the
 * compiler doesn't schedule branches.
 */
#ifdef SMALL_CACHE
static uint16
mul(register uint16 a, register uint16 b)
{
	register word32 p;

	p = (word32)a * b;
	if (p) {
		b = low16(p);
		a = p>>16;
		return (b - a) + (b < a);
	} else if (a) {
		return 1-b;
	} else {
		return 1-a;
	}
} /* mul */
#endif /* SMALL_CACHE */

/*
 * Expand a 128-bit user key to a working encryption key EK
 */
static void
ideaExpandKey(byte const *userkey, word16 *EK)
{
	int i,j;

	for (j=0; j<8; j++) {
		EK[j] = (userkey[0]<<8) + userkey[1];
		userkey += 2;
	}
	for (i=0; j < IDEAKEYLEN; j++) {
		i++;
		EK[i+7] = EK[i & 7] << 9 | EK[(i+1) & 7] >> 7;
		EK += i & 8;
		i &= 7;
	}
} /* ideaExpandKey */

/* This is not used at the moment, but may be later */
#if 0
/*
 * Compute the multiplicative inverse of x, modulo 65537, using Euclid's
 * algorithm. It is unrolled twice to avoid swapping the registers each
 * iteration, and some subtracts of t have been changed to adds.
 */
static uint16
mulInv(uint16 x)     
{
	uint16 t0, t1;
	uint16 q, y;

	if (x <= 1)
		return x;	/* 0 and 1 are self-inverse */
	t1 = 0x10001L / x;	/* Since x >= 2, this fits into 16 bits */
	y = 0x10001L % x;
	if (y == 1)
		return low16(1-t1);
	t0 = 1;
	do {
		q = x / y;
		x = x % y;
		t0 += q * t1;
		if (x == 1)
			return t0;
		q = y / x;
		y = y % x;
		t1 += q * t0;
	} while (y != 1);
	return low16(1-t1);
} /* mukInv */

/*
 * Compute IDEA decryption key DK from an expanded IDEA encryption key EK
 * Note that the input and output may be the same.  Thus, the key is
 * inverted into an internal buffer, and then copied to the output.
 */
static void
ideaInvertKey(word16 const *EK, word16 DK[IDEAKEYLEN])
{
	int i;
	uint16 t1, t2, t3;
	word16 temp[IDEAKEYLEN];
	word16 *p = temp + IDEAKEYLEN;

	t1 = mulInv(*EK++);
	t2 = -*EK++;
	t3 = -*EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;

	for (i = 0; i < IDEAROUNDS-1; i++) {
		t1 = *EK++;
		*--p = *EK++;
		*--p = t1;

		t1 = mulInv(*EK++);
		t2 = -*EK++;
		t3 = -*EK++;
		*--p = mulInv(*EK++);
		*--p = t2;
		*--p = t3;
		*--p = t1;
	}
	t1 = *EK++;
	*--p = *EK++;
	*--p = t1;

	t1 = mulInv(*EK++);
	t2 = -*EK++;
	t3 = -*EK++;
	*--p = mulInv(*EK++);
	*--p = t3;
	*--p = t2;
	*--p = t1;
/* Copy and destroy temp copy */
	memcpy(DK, temp, sizeof(temp));
    for (i = 0; i < IDEAKEYLEN; i++) {
        temp[i] = 0;
    }
//	burn(temp);
} /* ideaInvertKey */
#endif /* 0 */

/*
 * MUL(x,y) computes x = x*y, modulo 0x10001.  Requires two temps, 
 * t16 and t32.  x is modified, and must me a side-effect-free lvalue.
 * y may be anything, but unlike x, must be strictly 16 bits even if
 * low16() is #defined.
 * All of these are equivalent - see which is faster on your machine
 */
#ifdef SMALL_CACHE
#define MUL(x,y) (x = mul(low16(x),y))
#else /* !SMALL_CACHE */
#ifdef AVOID_JUMPS
#define MUL(x,y) (x = low16(x-1), t16 = low16((y)-1), \
		t32 = (word32)x*t16 + x + t16 + 1, x = low16(t32), \
		t16 = t32>>16, x = (x-t16) + (x<t16) )
#else /* !AVOID_JUMPS (default) */
#define MUL(x,y) \
	((t16 = (y)) ? \
		(x=low16(x)) ? \
			t32 = (word32)x*t16, \
			x = low16(t32), \
			t16 = t32>>16, \
	 		x = (x-t16)+(x<t16) \
		: \
			(x = 1-t16) \
	: \
		(x = 1-x))
#endif
#endif

/*	IDEA encryption/decryption algorithm */
/* Note that in and out can be the same buffer */
static void
ideaCipher(byte const (inbuf[8]), byte (outbuf[8]), word16 const *key)
{
	register uint16 x1, x2, x3, x4, s2, s3;
	word16 *in, *out;
#ifndef SMALL_CACHE
	register uint16 t16;	/* Temporaries needed by MUL macro */
	register word32 t32;
#endif
	int r = IDEAROUNDS;

	in = (word16 *)inbuf;
	x1 = *in++;  x2 = *in++;
	x3 = *in++;  x4 = *in;
#ifndef HIGHFIRST
	x1 = (x1 >>8) | (x1<<8);
	x2 = (x2 >>8) | (x2<<8);
	x3 = (x3 >>8) | (x3<<8);
	x4 = (x4 >>8) | (x4<<8);
#endif
	do {
		MUL(x1,*key++);
		x2 += *key++;
		x3 += *key++;
		MUL(x4, *key++);

		s3 = x3;
		x3 ^= x1;
		MUL(x3, *key++);
		s2 = x2;
		x2 ^= x4;
		x2 += x3;
		MUL(x2, *key++);
		x3 += x2;

		x1 ^= x2;  x4 ^= x3;

		x2 ^= s3;  x3 ^= s2;
	} while (--r);
	MUL(x1, *key++);
	x3 += *key++;
	x2 += *key++;
	MUL(x4, *key);

	out = (word16 *)outbuf;
#ifdef HIGHFIRST
	*out++ = x1;
	*out++ = x3;
	*out++ = x2;
	*out = x4;
#else /* !HIGHFIRST */
	*out++ = (x1 >>8) | (x1<<8);
	*out++ = (x3 >>8) | (x3<<8);
	*out++ = (x2 >>8) | (x2<<8);
	*out = (x4 >>8) | (x4<<8);
#endif
} /* ideaCipher */


void
ideaCfbReinit(struct IdeaCfbContext *context, byte const *iv)
{
	if (iv)
		memcpy(context->iv, iv, 8);
	else
		bzero(context->iv, 8);
	context->bufleft = 0;
}

void
ideaCfbInit(struct IdeaCfbContext *context, byte const (key[16]))
{
	ideaExpandKey(key, context->key);
	ideaCfbReinit(context,0);
}

void
ideaCfbDestroy(struct IdeaCfbContext *context)
{
//	burn(*context);
    int i;
    for (i = 0; i < 8; i++) {
        context->iv[i] = 0;
    }
    for (i = 0; i < IDEAKEYLEN; i++) {
        context->key[i] = 0;
    }
    context->bufleft = 0;
}

/*
 * Encrypt a buffer of data, using IDEA in CFB mode.
 * There are more compact ways of writing this, but this is
 * written for speed.
 */
void
ideaCfbEncrypt(struct IdeaCfbContext *context, byte const *src,
	       byte *dest, int count)
{
	int bufleft = context->bufleft;
	byte *bufptr = context->iv + 8-bufleft;

	/* If there are no more bytes to encrypt that there are bytes
	 * in the buffer, XOR them in and return.
	 */
	if (count <= bufleft) {
		context->bufleft = bufleft - count;
		while (count--) {
			*dest++ = *bufptr++ ^= *src++;
		}
		return;
	}
	count -= bufleft;
	/* Encrypt the first bufleft (0 to 7) bytes of the input by XOR
	 * with the last bufleft bytes in the iv buffer.
	 */
	while (bufleft--) {
		*dest++ = (*bufptr++ ^= *src++);
	}
	/* Encrypt middle blocks of the input by cranking the cipher,
	 * XORing 8-byte blocks, and repeating until the count
	 * is 8 or less.
	 */
	while (count > 8) {
		bufptr = context->iv;
		ideaCipher(bufptr, bufptr, context->key);
		bufleft = 8;
		count -= 8;
		do {
			*dest++ = (*bufptr++ ^= *src++);
		} while (--bufleft);
	}
	/* Do the last 1 to 8 bytes */
	bufptr = context->iv;
	ideaCipher(bufptr, bufptr, context->key);
	context->bufleft = 8-count;
	do  {
		*dest++ = (*bufptr++ ^= *src++);
	} while (--count);
}


/*
 * Decrypt a buffer of data, using IDEA in CFB mode.
 * There are more compact ways of writing this, but this is
 * written for speed.
 */
void
ideaCfbDecrypt(struct IdeaCfbContext *context, byte const *src,
	       byte *dest, int count)
{
	int bufleft = context->bufleft;
	static byte *bufptr;
	byte t;

	bufptr = context->iv + (8-bufleft);
	if (count <= bufleft) {
		context->bufleft = bufleft - count;
		while (count--) {
			t = *bufptr;
			*dest++ = t ^ (*bufptr++ = *src++);
		}
		return;
	}
	count -= bufleft;
	while (bufleft--) {
		t = *bufptr;
		*dest++ = t ^ (*bufptr++ = *src++);
	}
	while (count > 8) {
		bufptr = context->iv;
		ideaCipher(bufptr, bufptr, context->key);
		bufleft = 8;
		count -= 8;
		do {
			t = *bufptr;
			*dest++ = t ^ (*bufptr++ = *src++);
		} while (--bufleft);
	}
	bufptr = context->iv;
	ideaCipher(bufptr, bufptr, context->key);
	context->bufleft = 8-count;
	do {
		t = *bufptr;
		*dest++ = t ^ (*bufptr++ = *src++);
	} while (--count);
}

/********************************************************************/

/*
 * Initialize a cryptographic random-number generator.
 * key and seed should be arbitrary; timestamp should
 * be a current timestamp.
 */
void
ideaRandInit(struct IdeaRandContext *context, byte const (key[16]),
	     byte const (seed[8]), word32 timestamp)
{
	int i;

	ideaExpandKey(key, context->key);
	context->bufleft = 0;
	memcpy(context->internalbuf, seed, 8);
	for (i = 0; i < 8; i++) {
		context->timestamp[i] = (byte)timestamp;
		timestamp >>= 8;
	}
	ideaCipher(context->timestamp, context->timestamp, context->key);
}

/*
 * Cryptographic pseudo-random-number generator, used for generating
 * session keys.
 * Much of the design comes from Appendix C of ANSI X9.17.
 */
byte
ideaRandByte(struct IdeaRandContext *c)
{
	int i;

	if (!c->bufleft) {
		/* Compute next 8 bytes of output */
		for (i=0; i<8; i++)
			c->outbuf[i] = c->internalbuf[i] ^ c->timestamp[i];
		ideaCipher(c->outbuf, c->outbuf, c->key);
		/* Compute new seed vector */
		for (i=0; i<8; i++)
			c->internalbuf[i] = c->outbuf[i] ^ c->timestamp[i];
		ideaCipher(c->internalbuf, c->internalbuf, c->key);

		c->bufleft = 8;
	}
	return c->outbuf[--c->bufleft];
}

/* end of idea.c */

/********************************************/




static int idea_expmem()
{
  int tot = 0;

  return tot;
}

static void idea_report(int idx, int details)
{

  if (details) {
    dprintf(idx, "    idea encryption module\n");
  }
}

/* Convert 64-bit encrypted password to text for userfile */
static char *base64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define SALT1  0xdeadd061
#define SALT2  0x23f6b095

static int base64dec(char c)
{
  int i;

  for (i = 0; i < 64; i++)
    if (base64[i] == c)
      return i;
  return 0;
}

static void idea_encrypt_pass(char *text, char *new)
{
    MD5_CTX md5context;
    int i, n;
    char *p;
    unsigned char digest[16];
    u_32bit_t temp = 0;
    
    /* Generate 16 byte md5 sum from the pass */
    MD5_Init(&md5context);
    MD5_Update(&md5context, text, strlen(text));
    MD5_Final(digest, &md5context);
    
    p = new;
    *p++ = '+';         /* + means encrypted pass */
    for (i=0; i<4; i++) {
        bcopy(&(digest[i*4]), &temp, 4);
        n = 32;
        while (n > 0) {
            *p++ = base64[temp & 0x3f];
            temp = (temp >> 6);
            n -= 6;
        }
    }
    *p = 0;
}

/* Returned string must be freed when done with it!
 */
static char *encrypt_string(char *key, char *str)
{
  char *p;
  char *s, *dest, *d;
  int i,n;
  MD5_CTX md5context;
  unsigned char digest[16];
  struct IdeaCfbContext context;
  u_32bit_t temp = 0;
  /* Pad fake string with 8 bytes to make sure there's enough */
  s = (char *) nmalloc(strlen(str) + 9);
  strcpy(s, str);
  if ((!key) || (!key[0]))
    return s;
  p = s;
  dest = (char *) nmalloc((strlen(str) + 9) * 2);
  while (*p)
    p++;
  for (i = 0; i < 8; i++)
    *p++ = 0;
  p = s;
  d = dest;

  /* Generate 16 byte md5 sum from the pass */
  MD5_Init(&md5context);
  MD5_Update(&md5context, key, strlen(key));
  MD5_Final(digest, &md5context);

  ideaCfbInit(&context, digest);
  ideaCfbEncrypt(&context, (byte *)p, (byte *)p, strlen(p));
  ideaCfbDestroy(&context);
  
  for (i=0; i < (strlen(p) / 4)+1; i++) {
      bcopy(p + (i*4), &temp, 4);
        n = 32;
        while (n > 0) {
            *d++ = base64[temp & 0x3f];
            temp = (temp >> 6);
            n -= 6;
        }
  }
  *d = 0;
  nfree(s);
  return dest;
}

/* Returned string must be freed when done with it!
 */
static char *decrypt_string(char *key, char *str)
{
  char *p, *s, *dest, *d;
  int i;
  MD5_CTX md5context;
  unsigned char digest[16];
  struct IdeaCfbContext context;
  u_32bit_t temp = 0;

  /* Pad encoded string with 0 bits in case it's bogus */
  s = (char *) nmalloc(strlen(str) + 12);
  strcpy(s, str);
  if ((!key) || (!key[0]))
    return s;
  p = s;
  dest = (char *) nmalloc(strlen(str) + 12);
  while (*p)
    p++;
  for (i = 0; i < 12; i++)
    *p++ = 0;
  p = s;
  d = dest;
  
  while (*p) {
      temp = 0;
      for (i = 0; i < 6; i++)
          temp |= (base64dec(*p++)) << (i * 6);
      for (i = 0; i < 4; i++)
          *d++ = (temp & (0xff << ((i) * 8))) >> ((i) * 8);
  }
  *d = 0;

  /* Generate 16 byte md5 sum from the pass */
  MD5_Init(&md5context);
  MD5_Update(&md5context, key, strlen(key));
  MD5_Final(digest, &md5context);

  ideaCfbInit(&context, digest);
  ideaCfbDecrypt(&context, (byte *)dest, (byte *)dest, strlen(dest));
  ideaCfbDestroy(&context);
  
  debug1("return = %s", dest);
  nfree(s);
  return dest; 
}

static int tcl_encrypt STDVAR
{
  char *p;

  BADARGS(3, 3, " key string");
  p = encrypt_string(argv[1], argv[2]);
  Tcl_AppendResult(irp, p, NULL);
  nfree(p);
  return TCL_OK;
}

static int tcl_decrypt STDVAR
{
  char *p;

  BADARGS(3, 3, " key string");
  p = decrypt_string(argv[1], argv[2]);
  Tcl_AppendResult(irp, p, NULL);
  nfree(p);
  return TCL_OK;
}

static int tcl_encpass STDVAR
{
  BADARGS(2, 2, " string");
  if (strlen(argv[1]) > 0) {
    char p[16];
    idea_encrypt_pass(argv[1], p);
    Tcl_AppendResult(irp, p, NULL);
  } else
    Tcl_AppendResult(irp, "", NULL);
  return TCL_OK;
}

static tcl_cmds mytcls[] =
{
  {"encrypt",	tcl_encrypt},
  {"decrypt",	tcl_decrypt},
  {"encpass",	tcl_encpass},
  {NULL,	NULL}
};

static char *idea_close()
{
  return "You can't unload the encryption module";
}

EXPORT_SCOPE char *idea_start(Function *);

static Function idea_table[] =
{
  /* 0 - 3 */
  (Function) idea_start,
  (Function) idea_close,
  (Function) idea_expmem,
  (Function) idea_report,
  /* 4 - 7 */
  (Function) encrypt_string,
  (Function) decrypt_string,
};

char *idea_start(Function *global_funcs)
{

  /* `global_funcs' is NULL if eggdrop is recovering from a restart.
   *
   * As the encryption module is never unloaded, only initialise stuff
   * that got reset during restart, e.g. the tcl bindings.
   */
  if (global_funcs) {
    global = global_funcs;

    if (!module_rename("idea", MODULE_NAME))
      return "Already loaded.";
    /* Initialize buffered boxes */
    module_register(MODULE_NAME, idea_table, 2, 1);
    if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.8.0 or later.";
    }
    add_hook(HOOK_ENCRYPT_PASS, (Function) idea_encrypt_pass);
    add_hook(HOOK_ENCRYPT_STRING, (Function) encrypt_string);
    add_hook(HOOK_DECRYPT_STRING, (Function) decrypt_string);
  }
  add_tcl_commands(mytcls);
  return NULL;
}

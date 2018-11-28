# PBKDF2 for MySQL
PBKDF2 (Password-Based Key Derivation Function 2) is a key stretching algorithm to be used to hash e.g. passwords in a computationally intensive manner, so that dictionary and brute-force attacks are less effective.

The implementation for MySQL will be very slow using high number for iterations, so be careful to not slow down your MySQL server by extensive using this function.
This function was basically implemented to prefill empty password hash columns on tables by using `BEFORE INSERT` and `BEFORE UPDATE`triggers, when table columns are inserted or updated with plain passwords.

It is not a good idea to use PBKDF2 on MySQL by default, it's always better to use the PBKDF2 implemenation on client side using C, PHP, Javascript etc.
Also it's not recommend to use this function for queries from client to very if a password is valid; always use client local functions to build a PBKDF2 key from a given (input) password and stored salt and use this result within the MySQL query - otherwise you transfer the plain password over the network which may make the password hash algo useless.

* For further information about the algo see https://en.wikipedia.org/wiki/PBKDF2
* For a list of PBKDF2 implementations see https://en.wikipedia.org/wiki/List_of_PBKDF2_implementations

## Installation

Execute source from PBKDF2.sql, e.g.
```
mysql localhost --user yourname --password <PBKDF2.sql
```

## Usage

Use it like other internal MySQL functions:

`SELECT PBKDF2(algo, password, salt, count, key_length, raw_output);`
where
* `algo` - The hash algorithm to use (see enum for possible values). Recommended: 'SHA256'
* `password` - The password
* `salt` - A salt that is unique to the password
* `count` - Iteration count. Higher is better, but slower. Recommended: At least 1000
* `key_length` - The length of the derived key in bytes
* `raw_output` - If true, the key is returned in raw binary format, otherwise hex encoded

Returns a `key_length`-byte key derived from the password and salt.

Examples:

    SELECT CONVERT(PBKDF2('SHA256', 'password', 'salt', 1, 0, false) USING utf8);

returns `120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B`

To get a list of possible enum values for `algo` use  `CHECKSUM_HASH()` with `NULL` parameter:

    SELECT CONVERT(CHECKSUM_HASH(NULL,NULL) USING utf8);

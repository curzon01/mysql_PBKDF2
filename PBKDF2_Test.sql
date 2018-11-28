/* Some PBKDF2 HMAC Test Vectors */

/*
PBKDF2 HMAC-SHA256 Test Vectors

Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 1
  dkLen = 32

Output:
  DK = 12 0f b6 cf fc f8 b3 2c
       43 e7 22 52 56 c4 f8 37
       a8 65 48 c9 2c cc 35 48
       08 05 98 7c b7 0b e1 7b (32 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', 'password', 'salt', 1, 0, false) USING utf8)=UPPER('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
/*

Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 2
  dkLen = 32

Output:
  DK = ae 4d 0c 95 af 6b 46 d3
       2d 0a df f9 28 f0 6d d0
       2a 30 3f 8e f3 c2 51 df
       d6 e2 d8 5a 95 47 4c 43 (32 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', 'password', 'salt', 2, 32, false) USING utf8)=UPPER('ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');
/*


Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 4096
  dkLen = 32

Output:
  DK = c5 e4 78 d5 92 88 c8 41
       aa 53 0d b6 84 5c 4c 8d
       96 28 93 a0 01 ce 4e 11
       a4 96 38 73 aa 98 13 4a (32 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', 'password', 'salt', 4096, 32, false) USING utf8)=UPPER('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
/*


Input:
  P = "password" (8 octets)
  S = "salt" (4 octets)
  c = 16777216
  dkLen = 32

Output:
  DK = cf 81 c6 6f e8 cf c0 4d
       1f 31 ec b6 5d ab 40 89
       f7 f1 79 e8 9b 3b 0b cb
       17 ad 10 e3 ac 6e ba 46 (32 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', 'password', 'salt', 16777216, 32, false) USING utf8)=UPPER('cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46');
/*


Input:
  P = "passwordPASSWORDpassword" (24 octets)
  S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
  c = 4096
  dkLen = 40

Output:
  DK = 34 8c 89 db cb d3 2b 2f
       32 d8 14 b8 11 6e 84 cf
       2b 17 34 7e bc 18 00 18
       1c 4e 2a 1f b8 dd 53 e1
       c6 35 51 8c 7d ac 47 e9 (40 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40, false) USING utf8)=UPPER('348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9');
/*


Input:
  P = "pass\0word" (9 octets)
  S = "sa\0lt" (5 octets)
  c = 4096
  dkLen = 16

Output:
  DK = 89 b6 9d 05 16 f8 29 89
       3c 69 62 26 65 0a 86 87 (16 octets)
*/
SELECT CONVERT(system.PBKDF2('SHA256', CONCAT('pass',CHAR(0), 'word'), CONCAT('sa',CHAR(0), 'lt'), 4096, 16, false) USING utf8)=UPPER('89b69d0516f829893c696226650a8687');


/*
PBKDF2 HMAC-SHA512 Test Vectors

Input:
  P = "password"
  S = "salt"
  c = 1
  dkLen = 64

Output:
  DK = 86 7f 70 cf 1a de 02 cf
       f3 75 25 99 a3 a5 3d c4
       af 34 c7 a6 69 81 5a e5
       d5 13 55 4e 1c 8c f2 52
       c0 2d 47 0a 28 5a 05 01
       ba d9 99 bf e9 43 c0 8f
       05 02 35 d7 d6 8b 1d a5
       5e 63 f7 3b 60 a5 7f ce
*/
SELECT CONVERT(system.PBKDF2('SHA512', 'password', 'salt', 1, 64, false) USING utf8)=UPPER('867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce');
/*


Input:
  P = "password"
  S = "salt"
  c = 2
  dkLen = 64

Output:
  DK = e1 d9 c1 6a a6 81 70 8a
       45 f5 c7 c4 e2 15 ce b6
       6e 01 1a 2e 9f 00 40 71
       3f 18 ae fd b8 66 d5 3c
       f7 6c ab 28 68 a3 9b 9f
       78 40 ed ce 4f ef 5a 82
       be 67 33 5c 77 a6 06 8e
       04 11 27 54 f2 7c cf 4e
*/
SELECT CONVERT(system.PBKDF2('SHA512', 'password', 'salt', 2, 64, false) USING utf8)=UPPER('e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e');
/*


Input:
  P = "password"
  S = "salt"
  c = 4096
  dkLen = 64

Output:
  DK = d1 97 b1 b3 3d b0 14 3e
       01 8b 12 f3 d1 d1 47 9e
       6c de bd cc 97 c5 c0 f8
       7f 69 02 e0 72 f4 57 b5
       14 3f 30 60 26 41 b3 d5
       5c d3 35 98 8c b3 6b 84
       37 60 60 ec d5 32 e0 39
       b7 42 a2 39 43 4a f2 d5
*/
SELECT CONVERT(system.PBKDF2('SHA512', 'password', 'salt', 4096, 64, false) USING utf8)=UPPER('d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5');
/*


Input:
  P = "passwordPASSWORDpassword"
  S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
  c = 4096
  dkLen = 64

Output:
  DK = 8c 05 11 f4 c6 e5 97 c6
       ac 63 15 d8 f0 36 2e 22
       5f 3c 50 14 95 ba 23 b8
       68 c0 05 17 4d c4 ee 71
       11 5b 59 f9 e6 0c d9 53
       2f a3 3e 0f 75 ae fe 30
       22 5c 58 3a 18 6c d8 2b
       d4 da ea 97 24 a3 d3 b8
*/
SELECT CONVERT(system.PBKDF2('SHA512', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 64, false) USING utf8)=UPPER('8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8');
/*

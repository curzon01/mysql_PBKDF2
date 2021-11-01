CREATE DATABASE IF NOT EXISTS `system`;

USE `system`;

-- Dumping structure for function system.CHECKSUM_HASH
DELIMITER //
CREATE FUNCTION `CHECKSUM_HASH`(`str` MEDIUMBLOB, `algo` ENUM('MD5','SHA1','SHA224','SHA256','SHA384','SHA512')) RETURNS tinyblob
    NO SQL
    DETERMINISTIC
    COMMENT 'Returns a hash/checksum code based on algo'
BEGIN
    /*
     * CHECKSUM_HASH returns a checksum/hash of a given string using the choosen algo
     * str - The string to be hashed
     * algo - The hash algorithm to use.
     * For a list of possible algo call the function with NULL parameter, e.g. CHECKSUM_HASH(NULL,NULL)
     */
    IF str IS NULL OR algo is NULL THEN
        RETURN 'MD5 SHA1 SHA224 SHA256 SHA384 SHA512';
    END IF;

    CASE algo
        WHEN 'MD5' THEN RETURN MD5(str);
        WHEN 'SHA1' THEN RETURN SHA1(str);
        WHEN 'SHA224' THEN RETURN SHA2(str, 224);
        WHEN 'SHA256' THEN RETURN SHA2(str, 256);
        WHEN 'SHA384' THEN RETURN SHA2(str, 384);
        WHEN 'SHA512' THEN RETURN SHA2(str, 512);
        ELSE RETURN NULL;
    END CASE;

    RETURN NULL;
END//
DELIMITER ;


-- Dumping structure for function system.STRING_XOR
DELIMITER //
CREATE FUNCTION `STRING_XOR`(`string1` MEDIUMBLOB, `string2` MEDIUMBLOB) RETURNS mediumblob
    NO SQL
    DETERMINISTIC
    COMMENT 'XOR two binary strings'
BEGIN
    /*
     * STRING_XOR - XOR of two binary strings
     * string1, string2 - the two strings which are XORed byte for byte
     *
     * This function XOR each byte pof string1 with each byte of string2 and returns the result
     * If strings do not have the same length, the last byte of the least string will be used
     * to XOR with the rest of the greatest string.
     * So it can be used also to XOR a string with one constant byte, e.g. STRING_XOR(str1, CHAR(0x36));
     */
    DECLARE len, pos INT UNSIGNED;
    DECLARE result MEDIUMBLOB;

    SET len = GREATEST(LENGTH(string1),LENGTH(string2));
    SET result = '';
    SET pos = 1;
    WHILE pos <= len DO
        SET result = CONCAT(result,
                        CHAR(ORD(SUBSTR(string1, IF(pos>LENGTH(string1),LENGTH(string1),pos), 1)) ^
                             ORD(SUBSTR(string2, IF(pos>LENGTH(string2),LENGTH(string2),pos), 1))) );
        SET pos = pos + 1;
    END WHILE;

    RETURN result;
END//
DELIMITER ;


-- Dumping structure for function system.HMAC
DELIMITER //
CREATE FUNCTION `HMAC`(`algo` ENUM('MD5','SHA1','SHA224','SHA256','SHA384','SHA512'), `msg` MEDIUMBLOB, `msgkey` MEDIUMBLOB, `raw_output` TINYINT) RETURNS mediumblob
    NO SQL
    DETERMINISTIC
    COMMENT 'Generate a keyed hash value using the HMAC method'
BEGIN
    /*
     * HMAC hash function
     * algo - The hash algorithm to use (see enum for possible values). Recommended: 'SHA256'
     * msg - Message to be hashed.
     * msgkey - Shared secret key used for generating the HMAC variant of the message digest.
     * count - Iteration count. Higher is better, but slower. Recommended: At least 1000
     * key_length - The length of the derived key in bytes
     * raw_output - If true, the key is returned in raw binary format, otherwise hex encoded
     * Returns: A string containing the calculated message digest.
     */
    DECLARE hashlen INT UNSIGNED;
    DECLARE opad, ipad TINYBLOB;
    DECLARE res TINYBLOB;

    SET hashlen = POW(2,CEIL(LOG2( LENGTH(CHECKSUM_HASH('',algo)) )));

    IF LENGTH(msgkey) > hashlen THEN
        SET msgkey = UNHEX(CHECKSUM_HASH(msgkey, algo));
    END IF;

    SET msgkey = RPAD(msgkey, hashlen, 0x00);

    SET ipad = STRING_XOR(msgkey, CHAR(0x36));
    SET opad = STRING_XOR(msgkey, CHAR(0x5C));

    SET res = CHECKSUM_HASH( CONCAT(opad, UNHEX( CHECKSUM_HASH(CONCAT(ipad, msg), algo) )), algo );

    IF raw_output THEN
        RETURN UNHEX(res);
    ELSE
        RETURN res;
    END IF;
END//
DELIMITER ;


-- Dumping structure for function system.PBKDF2
DELIMITER //
CREATE FUNCTION `PBKDF2`(`algo` ENUM('MD5','SHA1','SHA224','SHA256','SHA384','SHA512'), `password` MEDIUMBLOB, `salt` MEDIUMBLOB, `count` INT, `key_length` INT, `raw_output` INT) RETURNS mediumblob
    NO SQL
    DETERMINISTIC
BEGIN
    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * algo - The hash algorithm to use (see enum for possible values). Recommended: 'SHA256'
     * password - The password
     * salt - A salt that is unique to the password
     * count - Iteration count. Higher is better, but slower. Recommended: At least 1000
     * key_length - The length of the derived key in bytes
     * raw_output - If true, the key is returned in raw binary format, otherwise hex encoded
     * Returns: A key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca (https://defuse.ca/php-pbkdf2.htm)
     * With improvements by http://www.variations-of-shadow.com and
     */

    DECLARE i, j, k, block_count, hashlen INT UNSIGNED;
    DECLARE output, last, xorsum MEDIUMBLOB;

    SET hashlen = POW(2,CEIL(LOG2( LENGTH(CHECKSUM_HASH('',algo)) )));

    IF key_length=0 THEN
        SET key_length = hashlen;
    END IF;
    SET block_count = CEIL(key_length / hashlen);

    SET output = "";
    SET i = 1;
    WHILE (i <= block_count) DO
        -- i encoded as 4 bytes, big endian.
        SET last = CONCAT(salt, UNHEX(LPAD(HEX(i),8,'0')) );
        -- first iteration
        SET last = HMAC(algo, last, password, true);
        SET xorsum = last;
        -- perform the (count - 1) XOR iterations
        SET j = 1;
        WHILE (j < count) DO
            SET last = HMAC(algo, last, password, true);
            SET xorsum = STRING_XOR(xorsum, last);
            SET j = j + 1;
        END WHILE;
        SET output = CONCAT(output,xorsum);
        SET i = i + 1;
    END WHILE;

    IF raw_output THEN
        RETURN LEFT(output, key_length);
    ELSE
        RETURN LOWER(CONVERT(HEX(LEFT(output, key_length)) USING utf8));
    END IF;
END//
DELIMITER ;

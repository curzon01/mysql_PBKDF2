# PBKDF2 For MySQL
PBKDF2 (Password-Based Key Derivation Function 2) is a key stretching algorithm to be used used to hash passwords in a computationally intensive manner, so that dictionary and brute-force attacks are less effective.

The implemenation for MySQL is slow using high counts of iterations, so be careful to not slow down your MySQL server using this function. It was basically implemented to only prefill empty password fields on tables using triggers. It is not a good idea to use PBKDF2 on MySQL by default. It is always better to use the PBKDF2 implemenation on client side using C, PHP, Javascript etc.
For further information about the algo see https://en.wikipedia.org/wiki/PBKDF2
For a list of PBKDF2 implementations see https://en.wikipedia.org/wiki/List_of_PBKDF2_implementations


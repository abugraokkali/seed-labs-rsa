#include "rsa.c"

int main()
{
	/* Task 3: Decrypting a Message */

	// Assign the first large prime
	BIGNUM *p = BN_new();
	BN_hex2bn(&p, "C353136B52414B12B4149F7FA641AE97A07C98292D4358227DFE0EA3BC4DAD7F");

	// Assign the second large prime
	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "F555DEEF7084C34D2FB95C3B942BB4CCF06A8FD18CE63A87D63275CE06FE28BF");

	// Assign the Modulus
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "010001");

	BIGNUM *n = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_mul(n, p, q, ctx);

	// We are going to encrypt the message 'Bu da ikinci gizli mesaj'.
	// We can convert the hex into a BIGNUM for the computations.
	BIGNUM *enc = BN_new();
	BN_hex2bn(&enc, "7AA0FF25F5D5C94FBEA7109F8AA34A43ADA883EF30CE12A4595BBD92D36D91FBE43A841400345177D6572F6587882FAB78549D6155500F9D319F892F8E74F07F");

	// Decryption
	BIGNUM *d = BN_new();
	d = get_rsa_priv_key(p, q, e);

	BIGNUM *dec = BN_new();
	dec = rsa_decrypt(enc, d, n);
	printf("the decrypted message for is: ");
	printHX(BN_bn2hex(dec));
}
#include "rsa.c"

int main()
{
    /* Task 2 - Encrypting a Message by Derived Key */

    // Assign the first large prime
    BIGNUM *p = BN_new();
    BN_hex2bn(&p, "C353136B52414B12B4149F7FA641AE97A07C98292D4358227DFE0EA3BC4DAD7F");

    // Assign the second large prime
    BIGNUM *q = BN_new();
    BN_hex2bn(&q, "F555DEEF7084C34D2FB95C3B942BB4CCF06A8FD18CE63A87D63275CE06FE28BF");

    // Assign the Modulus
    BIGNUM *e = BN_new();
    BN_hex2bn(&e, "010001");

    // We are going to encrypt the message 'Bu da ikinci gizli mesaj'.
    // We can convert the hex into a BIGNUM for the computations.
    BIGNUM *M = BN_new();
    BN_hex2bn(&M, "427520646120696B696E63692067697A6C69206D6573616A");

    BIGNUM *n = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mul(n, p, q, ctx);

    BIGNUM *enc = BN_new();
    enc = rsa_encrypt(M, e, n);
    printBN("the encrypted message is: ", enc);

    /* Decryption

    BIGNUM *d = BN_new();
    BIGNUM *dec = BN_new();
    d = get_rsa_priv_key(p, q, e);
    dec = rsa_decrypt(enc, d, n);
    printf("the decrypted message for is: ");
    printHX(BN_bn2hex(dec));
    */
}
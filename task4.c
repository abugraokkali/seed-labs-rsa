#include "rsa.c"

int main()
{
    /* Task 4: Signing a Message */

    // Assign the first large prime
    BIGNUM *p = BN_new();
    BN_hex2bn(&p, "C353136B52414B12B4149F7FA641AE97A07C98292D4358227DFE0EA3BC4DAD7F");

    // Assign the second large prime
    BIGNUM *q = BN_new();
    BN_hex2bn(&q, "F555DEEF7084C34D2FB95C3B942BB4CCF06A8FD18CE63A87D63275CE06FE28BF");

    // Assign the Modulus
    BIGNUM *e = BN_new();
    BN_hex2bn(&e, "010001");

    // Calculate p * q
    BIGNUM *n = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mul(n, p, q, ctx);

    // The message is "Sana 1 milyon lira borcum var". First we must convert this to hex.
    // $ python3
    // >>> import binascii
    // >>> x=b'Sana 1 milyon lira borcum var'
    // >>> x=binascii.hexlify(x)
    // >>> x
    // b'53616e612031206d696c796f6e206c69726120626f7263756d20766172'
    // Once we have the hex, we convert to a BIGNUM for the computations.
    BIGNUM *M = BN_new();
    BN_hex2bn(&M, "53616e612031206d696c796f6e206c69726120626f7263756d20766172");

    BIGNUM *M2 = BN_new();
    BN_hex2bn(&M2, "53616e612031206d696c796f6e206c69726120626f7263756d20766171");

    BIGNUM *d = BN_new();
    d = get_rsa_priv_key(p, q, e);

    // Since we already have the private key, all we need to do is encrypt.
    BIGNUM *enc = BN_new();
    enc = rsa_encrypt(M, d, n);
    printBN("the first signature is: ", enc);

    // To verify the operations were conducted correctly, we decrypt as well.
    BIGNUM *dec = BN_new();
    dec = rsa_decrypt(enc, e, n);
    printf("the first message is: ");
    printHX(BN_bn2hex(dec));

    printf("\n");

    enc = rsa_encrypt(M2, d, n);
    printBN("the second signature is: ", enc);
    dec = rsa_decrypt(enc, e, n);
    printf("the second message is: ");
    printHX(BN_bn2hex(dec));
}
#include "rsa.c"

int main()
{
    /* Task 1 - Encrypting a message */

    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();

    // Assign the private key
    BIGNUM *d = BN_new();
    BN_hex2bn(&d, "8D017DAF61EB9E6E08A74841F2F9B2F50D6913D605C98E416E06D8441DDBE94F5F058E2FF8B629B59C98D4A6B799909455018CDE39C9FC3A4A74A6E483E45C07");

    // Assign the public key
    BIGNUM *n = BN_new();
    BN_hex2bn(&n, "BB300643E39AA365612115898C2737D969635148A40AAAD9F2A92E60A7BB1BB7DA9A09F339FE02761FF451FF0FAFAFEA1C792D3C0114B2D4234FCFEABF1249C1");
    printBN("the public key is: ", n);

    // Assign the Modulus
    BIGNUM *e = BN_new();
    BN_hex2bn(&e, "0D88C3");

    // We are going to encrypt the message 'Acayip gizli bir mesaj!'.
    // We can convert the hex into a BIGNUM for the computations.
    BIGNUM *M = BN_new();
    BN_hex2bn(&M, "4163617969702067697a6c6920626972206d6573616a21");

    printBN("the plaintext message is: ", M);
    enc = rsa_encrypt(M, e, n);
    printBN("the encrypted message is: ", enc);
    dec = rsa_decrypt(enc, d, n);
    printf("the decrypted message is: ");
    printHX(BN_bn2hex(dec));
}
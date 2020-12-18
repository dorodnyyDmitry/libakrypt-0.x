#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>


int main(){

    char *dummy_key =  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    char *dummy_nonce= "000000000001020304050607";
    char *msg = "Dorodnyy Dmitry Higher school of economics 2020";

    poly1305_mac(msg, dummy_key, dummy_nonce);
    return 0;
}

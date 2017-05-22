#include <stdlib.h>
#include <string.h>

#include "sock.h"
#include "logger.h"
#include "gpg.h"

#define MAX_BUF (1024 * 8)
#define GPG_PRIV_KEY "priv.key"
#define GPG_PUB_KEY "pub.key"
char *pattern = "-----END PGP MESSAGE-----";

int main(int argc, char *argv[])
{
    int ret, port, fd;
    char buf[MAX_BUF];
    char *ip, *srv_keypath, *username, *newflag;
    char *fpr, *cipher, *sign, *plain, *cipher_json;

    /* check args */
    if (argc < 5) {
        log_errf("usage: %s <ip> <port> <srv.key> <username>", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* get args */
    ip = strdup(argv[1]);
    port = atoi(argv[2]);
    srv_keypath = strdup(argv[3]);
    cli_username = strdup(argv[4]);
    newflag = "SOMEFLAGBRUH";

    /* init */
    gpg_init(GPG_PRIV_KEY);

    /* try to find key */
    ret = gpg_import_key(srv_keypath, &fpr);
    if (ret != 0) {
        log_warnf("failed to find key '%s'", srv_keypath);
        return -1;
    }

    log_infof("server key %s", fpr);

    /* connect */
    sock_connect(&fd, ip, port);

    /* get prompt */
    bzero(buf, MAX_BUF);
    sock_read(fd, buf, MAX_BUF);
    log_infof("got: %s", buf);

    /* send username */
    sprintf(buf, "%s\n", username);
    sock_write(fd, buf, strlen(buf));

    /* read challenge */
    bzero(buf, MAX_BUF);
    sock_read_multiline(fd, buf, MAX_BUF, pattern);
    log_infof("got: %s", buf);
    cipher = strdup(buf);

    /* decrypt */
    ret = gpg_decrypt(cipher, &sign);
    /* log_infof("decrypted:\n%s", sign); */
    if (ret < 0) {
        log_err("decryption failed");
        return -1;
    }

    /* verify */
    ret = gpg_verify(fpr, sign, &plain);
    /* log_infof("verified:\n%s", plain); */
    if (ret < 0) {
        log_err("verification failed");
        return -1;
    }

    log_infof("got number:\n%s", plain);

    /* sign */
    ret = gpg_sign(plain, strlen(plain), &sign);
    /* log_infof("resigned:\n%s", sign); */
    if (ret < 0) {
        log_err("resign failed");
        return -1;
    }

    /* encrypt */
    ret = gpg_encrypt(fpr, sign, strlen(sign), &cipher);
    /* log_infof("reencrypted:\n%s", cipher); */
    if (ret < 0) {
        log_err("reencryption failed");
        return -1;
    }

    /* send answer */
    sock_write(fd, cipher, strlen(cipher));

    /* get final answer */
    bzero(buf, MAX_BUF);
    sock_read(fd, buf, MAX_BUF);

    log_infof("got final answer: %s", buf);

    /* construct json */
    bzero(buf, MAX_BUF);
    sprintf(buf, "{"
            "\"signer\": \"%s\","
            "\"newflag\": \"%s\","
            "\"signature\": \"%s:%s\""
            "}\n", username, newflag, username, newflag);

    /* encrypt json */
    ret = gpg_encrypt(fpr, buf, strlen(buf), &cipher_json);
    if (ret < 0) {
        log_err("failed to encrypt json");
        return -1;
    }

    /* send encrypted json */
    sock_write(fd, cipher_json, strlen(cipher_json));

    log_infof("sending json:\n%s", buf);

    /* clean up */
    gpg_free();

    return 0;
}

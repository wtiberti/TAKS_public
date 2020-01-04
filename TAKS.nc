#include <stdlib.h>

interface TAKS {
	command void ComponentFromHexString(uint8_t *data, const char *s);
	command int Encrypt(uint8_t *out_ciphertext, uint8_t *plaintext, size_t size, uint8_t * out_mac, uint8_t *out_kri, uint8_t *src_LKC, uint8_t *dst_TKC, uint8_t *dst_TV);
	command int Decrypt(uint8_t *out_plaintext, uint8_t *ciphertext, size_t size, uint8_t *mac, uint8_t *kri, uint8_t *node_LKC);
	command int Encrypt_pw(uint8_t *out_ciphertext, uint8_t *plaintext, size_t size, uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, uint8_t *src_TKC, uint8_t *dst_TKC);
	command int Decrypt_pw(uint8_t *out_plaintext, uint8_t *ciphertext, size_t size, uint8_t *mac, uint8_t *kri, uint8_t *node_LKC);
}

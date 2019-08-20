/* CFLAGS: -I/usr/lib/gcc/x86_64-pc-linux-gnu/9.1.0/include */
/* CFLAGS: -I/usr/local/include */
/* CFLAGS: -I/usr/lib/gcc/x86_64-pc-linux-gnu/9.1.0/include-fixed */
/* CFLAGS: -I/usr/include */
/* LIBS: monocypher */
#include "monocypher.h"

int 
monocypher$crypto_verify16(uint8_t (*_a0), uint8_t (*_a1))
{
	return crypto_verify16(_a0, _a1);
}
int 
monocypher$crypto_verify32(uint8_t (*_a0), uint8_t (*_a1))
{
	return crypto_verify32(_a0, _a1);
}
int 
monocypher$crypto_verify64(uint8_t (*_a0), uint8_t (*_a1))
{
	return crypto_verify64(_a0, _a1);
}
void 
monocypher$crypto_wipe(void (*_a0), size_t _a1)
{
	return crypto_wipe(_a0, _a1);
}
void 
monocypher$crypto_lock(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4), size_t _a5)
{
	return crypto_lock(_a0, _a1, _a2, _a3, _a4, _a5);
}
int 
monocypher$crypto_unlock(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4), size_t _a5)
{
	return crypto_unlock(_a0, _a1, _a2, _a3, _a4, _a5);
}
void 
monocypher$crypto_lock_aead(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4), size_t _a5, uint8_t (*_a6), size_t _a7)
{
	return crypto_lock_aead(_a0, _a1, _a2, _a3, _a4, _a5, _a6, _a7);
}
int 
monocypher$crypto_unlock_aead(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4), size_t _a5, uint8_t (*_a6), size_t _a7)
{
	return crypto_unlock_aead(_a0, _a1, _a2, _a3, _a4, _a5, _a6, _a7);
}
void 
monocypher$crypto_lock_init(crypto_lock_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_lock_init(_a0, _a1, _a2);
}
void 
monocypher$crypto_lock_auth_ad(crypto_lock_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_lock_auth_ad(_a0, _a1, _a2);
}
void 
monocypher$crypto_lock_auth_message(crypto_lock_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_lock_auth_message(_a0, _a1, _a2);
}
void 
monocypher$crypto_lock_update(crypto_lock_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), size_t _a3)
{
	return crypto_lock_update(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_lock_final(crypto_lock_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_lock_final(_a0, _a1);
}
void 
monocypher$crypto_unlock_update(crypto_lock_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), size_t _a3)
{
	return crypto_unlock_update(_a0, _a1, _a2, _a3);
}
int 
monocypher$crypto_unlock_final(crypto_lock_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_unlock_final(_a0, _a1);
}
void 
monocypher$crypto_blake2b(uint8_t (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_blake2b(_a0, _a1, _a2);
}
void 
monocypher$crypto_blake2b_general(uint8_t (*_a0), size_t _a1, uint8_t (*_a2), size_t _a3, uint8_t (*_a4), size_t _a5)
{
	return crypto_blake2b_general(_a0, _a1, _a2, _a3, _a4, _a5);
}
void 
monocypher$crypto_blake2b_init(crypto_blake2b_ctx (*_a0))
{
	return crypto_blake2b_init(_a0);
}
void 
monocypher$crypto_blake2b_update(crypto_blake2b_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_blake2b_update(_a0, _a1, _a2);
}
void 
monocypher$crypto_blake2b_final(crypto_blake2b_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_blake2b_final(_a0, _a1);
}
void 
monocypher$crypto_blake2b_general_init(crypto_blake2b_ctx (*_a0), size_t _a1, uint8_t (*_a2), size_t _a3)
{
	return crypto_blake2b_general_init(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_argon2i(uint8_t (*_a0), uint32_t _a1, void (*_a2), uint32_t _a3, uint32_t _a4, uint8_t (*_a5), uint32_t _a6, uint8_t (*_a7), uint32_t _a8)
{
	return crypto_argon2i(_a0, _a1, _a2, _a3, _a4, _a5, _a6, _a7, _a8);
}
void 
monocypher$crypto_argon2i_general(uint8_t (*_a0), uint32_t _a1, void (*_a2), uint32_t _a3, uint32_t _a4, uint8_t (*_a5), uint32_t _a6, uint8_t (*_a7), uint32_t _a8, uint8_t (*_a9), uint32_t _a10, uint8_t (*_a11), uint32_t _a12)
{
	return crypto_argon2i_general(_a0, _a1, _a2, _a3, _a4, _a5, _a6, _a7, _a8, _a9, _a10, _a11, _a12);
}
int 
monocypher$crypto_key_exchange(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_key_exchange(_a0, _a1, _a2);
}
void 
monocypher$crypto_sign_public_key(uint8_t (*_a0), uint8_t (*_a1))
{
	return crypto_sign_public_key(_a0, _a1);
}
void 
monocypher$crypto_sign(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), size_t _a4)
{
	return crypto_sign(_a0, _a1, _a2, _a3, _a4);
}
int 
monocypher$crypto_check(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2), size_t _a3)
{
	return crypto_check(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_sign_init_first_pass(crypto_sign_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_sign_init_first_pass(_a0, _a1, _a2);
}
void 
monocypher$crypto_sign_update(crypto_sign_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_sign_update(_a0, _a1, _a2);
}
void 
monocypher$crypto_sign_init_second_pass(crypto_sign_ctx (*_a0))
{
	return crypto_sign_init_second_pass(_a0);
}
void 
monocypher$crypto_sign_final(crypto_sign_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_sign_final(_a0, _a1);
}
void 
monocypher$crypto_check_init(crypto_check_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_check_init(_a0, _a1, _a2);
}
void 
monocypher$crypto_check_update(crypto_check_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_check_update(_a0, _a1, _a2);
}
int 
monocypher$crypto_check_final(crypto_check_ctx (*_a0))
{
	return crypto_check_final(_a0);
}
void 
monocypher$crypto_kex_xk1_init_client(crypto_kex_client_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4))
{
	return crypto_kex_xk1_init_client(_a0, _a1, _a2, _a3, _a4);
}
void 
monocypher$crypto_kex_xk1_init_server(crypto_kex_server_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3))
{
	return crypto_kex_xk1_init_server(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_kex_xk1_1(crypto_kex_client_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_kex_xk1_1(_a0, _a1);
}
void 
monocypher$crypto_kex_xk1_2(crypto_kex_server_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_kex_xk1_2(_a0, _a1, _a2);
}
int 
monocypher$crypto_kex_xk1_3(crypto_kex_client_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3))
{
	return crypto_kex_xk1_3(_a0, _a1, _a2, _a3);
}
int 
monocypher$crypto_kex_xk1_4(crypto_kex_server_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3))
{
	return crypto_kex_xk1_4(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_kex_x_init_client(crypto_kex_client_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3), uint8_t (*_a4))
{
	return crypto_kex_x_init_client(_a0, _a1, _a2, _a3, _a4);
}
void 
monocypher$crypto_kex_x_init_server(crypto_kex_server_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_kex_x_init_server(_a0, _a1, _a2);
}
void 
monocypher$crypto_kex_x_1(crypto_kex_client_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_kex_x_1(_a0, _a1, _a2);
}
int 
monocypher$crypto_kex_x_2(crypto_kex_server_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), uint8_t (*_a3))
{
	return crypto_kex_x_2(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_chacha20_H(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_chacha20_H(_a0, _a1, _a2);
}
void 
monocypher$crypto_chacha20_init(crypto_chacha_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_chacha20_init(_a0, _a1, _a2);
}
void 
monocypher$crypto_chacha20_x_init(crypto_chacha_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_chacha20_x_init(_a0, _a1, _a2);
}
void 
monocypher$crypto_chacha20_set_ctr(crypto_chacha_ctx (*_a0), uint64_t _a1)
{
	return crypto_chacha20_set_ctr(_a0, _a1);
}
void 
monocypher$crypto_chacha20_encrypt(crypto_chacha_ctx (*_a0), uint8_t (*_a1), uint8_t (*_a2), size_t _a3)
{
	return crypto_chacha20_encrypt(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_chacha20_stream(crypto_chacha_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_chacha20_stream(_a0, _a1, _a2);
}
void 
monocypher$crypto_poly1305(uint8_t (*_a0), uint8_t (*_a1), size_t _a2, uint8_t (*_a3))
{
	return crypto_poly1305(_a0, _a1, _a2, _a3);
}
void 
monocypher$crypto_poly1305_init(crypto_poly1305_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_poly1305_init(_a0, _a1);
}
void 
monocypher$crypto_poly1305_update(crypto_poly1305_ctx (*_a0), uint8_t (*_a1), size_t _a2)
{
	return crypto_poly1305_update(_a0, _a1, _a2);
}
void 
monocypher$crypto_poly1305_final(crypto_poly1305_ctx (*_a0), uint8_t (*_a1))
{
	return crypto_poly1305_final(_a0, _a1);
}
void 
monocypher$crypto_x25519_public_key(uint8_t (*_a0), uint8_t (*_a1))
{
	return crypto_x25519_public_key(_a0, _a1);
}
int 
monocypher$crypto_x25519(uint8_t (*_a0), uint8_t (*_a1), uint8_t (*_a2))
{
	return crypto_x25519(_a0, _a1, _a2);
}

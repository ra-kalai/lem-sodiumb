/*
* This file is part of lem-sodiumb.
* Copyright 2018 Ralph Augé
*
* lem-sodium is free software: you can redistribute it and/or
* modify it under the terms of the GNU General Public License as
* published by the Free Software Foundation, either version 3 of
* the License, or (at your option) any later version.
*
* lem-sodium is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with lem-sodiumb. If not, see <http://www.gnu.org/licenses/>.
*/

#include <lem.h>
#include <sodium.h>

static int
lem_sodiumb_crypto_box_keypair(lua_State *T) {
  unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretKey[crypto_box_SECRETKEYBYTES];

  crypto_box_keypair(publicKey, secretKey);

  lua_createtable(T, 0, 4);
  lua_pushlstring(T, (const char*)publicKey, crypto_box_PUBLICKEYBYTES);
  lua_setfield(T, -2, "publicKey");
  lua_pushlstring(T, (const char*)secretKey, crypto_box_SECRETKEYBYTES);
  lua_setfield(T, -2, "privateKey");

  return 1;
}

static int
lem_sodiumb_crypto_secretbox_keygen(lua_State *T) {
  unsigned char key[crypto_secretbox_KEYBYTES];

  crypto_secretbox_keygen(key);

  lua_pushlstring(T, (const char*)key, crypto_secretbox_KEYBYTES);

  return 1;
}

static int
lem_sodiumb_crypto_secretbox_easy(lua_State *T) {
  size_t msg_len;
  const char *msg = lua_tolstring(T, 1, &msg_len);

  size_t ciphertext_len = msg_len + crypto_secretbox_MACBYTES;
  unsigned char ciphertext[ciphertext_len];

  size_t nonce_len;
  const char *nonce = lua_tolstring(T, 2, &nonce_len);
  if (nonce_len != crypto_box_NONCEBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid nonce");
    return 2;
  }

  size_t key_len;
  const char *key = lua_tolstring(T, 3, &key_len);
  if (key_len != crypto_secretbox_KEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid key");
    return 2;
  }

  crypto_secretbox_easy(ciphertext, (const unsigned char*)msg, msg_len, (const unsigned char*)nonce, (const unsigned char*)key);

  lua_pushlstring(T, (const char*)ciphertext, ciphertext_len);

  return 1;
}

static int
lem_sodiumb_crypto_secretbox_open_easy(lua_State *T) {
  size_t ciphertext_len;
  const char *ciphertext = lua_tolstring(T, 1, &ciphertext_len);

  if (ciphertext_len < crypto_secretbox_MACBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid ciphertext ; too short");
    return 2;
  }

  size_t nonce_len;
  const char *nonce = lua_tolstring(T, 2, &nonce_len);
  if (nonce_len != crypto_box_NONCEBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid nonce");
    return 2;
  }

  size_t key_len;
  const char *key = lua_tolstring(T, 3, &key_len);

  if (key_len != crypto_secretbox_KEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid key");
    return 2;
  }

  size_t decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;
  unsigned char decrypted[decrypted_len];

  if (crypto_secretbox_open_easy(decrypted, (const unsigned char *)ciphertext, ciphertext_len, (const unsigned char *)nonce, (const unsigned char *)key)) {
    lua_pushnil(T);
    lua_pushstring(T, "message forged");
    return 2;
  }

  lua_pushlstring(T, (const char*)decrypted, decrypted_len);
  return 1;
}

static int
lem_sodiumb_randombytes_buf(lua_State *T) {
  int len = lua_tointeger(T, 1);
  unsigned char buf[len];
  randombytes_buf(buf, len);
  lua_pushlstring(T, (const char*)buf, len);
  return 1;
}

static int
lem_sodiumb_crypto_box_easy(lua_State *T) {
  size_t msg_len;
  const char *msg = lua_tolstring(T, 1, &msg_len);

  size_t ciphertext_len = crypto_box_MACBYTES + msg_len;
  unsigned char ciphertext[ciphertext_len];

  size_t nonce_len;
  const char *nonce = lua_tolstring(T, 2, &nonce_len);
  if (nonce_len != crypto_box_NONCEBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid nonce");
    return 2;
  }

  size_t publicKey_len;
  const char *publicKey = lua_tolstring(T, 3, &publicKey_len);
  if (publicKey_len != crypto_box_PUBLICKEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid public key");
    return 2;
  }

  size_t privateKey_len;
  const char *privateKey = lua_tolstring(T, 4, &privateKey_len);
  if (privateKey_len != crypto_box_SECRETKEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid secret key");
    return 2;
  }

  /*
     fprintf(stderr,"msg_len=%d ciphertext_len=%d nonce_len=%d publicKey_len=%d, privateKey_len=%d - %d-%d-%d\n",
     msg_len, ciphertext_len, nonce_len, publicKey_len, privateKey_len, crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES, crypto_box_NONCEBYTES);
     */

  if (crypto_box_easy(ciphertext, (unsigned char*)msg, msg_len, (unsigned char*)nonce,
        (unsigned char*)publicKey, (unsigned char*)privateKey) != 0) {
    lua_pushnil(T);
    lua_pushstring(T, "message forged");
    return 2;
  }

  lua_pushlstring(T, (const char*)ciphertext, ciphertext_len);
  return 1;
}

static int
lem_sodiumb_crypto_box_open_easy(lua_State *T) {
  size_t ciphertext_len;
  const char *ciphertext = lua_tolstring(T, 1, &ciphertext_len);
  if (ciphertext_len < crypto_secretbox_MACBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid ciphertext ; too short");
    return 2;
  }

  size_t nonce_len;
  const char *nonce = lua_tolstring(T, 2, &nonce_len);
  if (nonce_len != crypto_box_NONCEBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid nonce");
    return 2;
  }

  size_t publicKey_len;
  const char *publicKey = lua_tolstring(T, 3, &publicKey_len);
  if (publicKey_len != crypto_box_PUBLICKEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid public key");
    return 2;
  }

  size_t privateKey_len;
  const char *privateKey = lua_tolstring(T, 4, &privateKey_len);
  if (privateKey_len != crypto_box_SECRETKEYBYTES) {
    lua_pushnil(T);
    lua_pushstring(T, "invalid secret key");
    return 2;
  }

  size_t decrypted_len = ciphertext_len-crypto_box_MACBYTES;
  unsigned char decrypted[decrypted_len];

  if (crypto_box_open_easy(decrypted, (unsigned char*)ciphertext, ciphertext_len, (unsigned char*)nonce,
        (unsigned char*)publicKey, (unsigned char*)privateKey) != 0) {
    lua_pushnil(T);
    lua_pushstring(T, "message forged");
    return 2;
  }

  lua_pushlstring(T, (const char*)decrypted, decrypted_len);
  return 1;
}

static const luaL_Reg lem_sodiumb_core_export[] = {
  {"crypto_secretbox_keygen",  lem_sodiumb_crypto_secretbox_keygen},
  {"crypto_secretbox_easy",  lem_sodiumb_crypto_secretbox_easy},
  {"crypto_secretbox_open_easy",  lem_sodiumb_crypto_secretbox_open_easy},
  {"crypto_box_keypair",  lem_sodiumb_crypto_box_keypair},
  {"crypto_box_easy",  lem_sodiumb_crypto_box_easy},
  {"crypto_box_open_easy",  lem_sodiumb_crypto_box_open_easy},
  {"randombytes_buf",  lem_sodiumb_randombytes_buf},
  {NULL, NULL },
};

static void
h_set_methods(lua_State *L, const luaL_Reg *func_list) {
  for(;*func_list->func!=NULL;func_list++) {
    lua_pushcfunction(L, func_list->func);
    lua_setfield(L, -2, func_list->name);
  }
}

int
luaopen_lem_sodiumb_core(lua_State *L) {
  if (sodium_init() < 0) {
    lua_pushnil(L);
    return 1;
  }

  lua_newtable(L);
  h_set_methods(L, lem_sodiumb_core_export);

  lua_pushinteger(L, crypto_box_NONCEBYTES);
  lua_setfield(L, -2, "crypto_box_NONCEBYTES");

  return 1;
}

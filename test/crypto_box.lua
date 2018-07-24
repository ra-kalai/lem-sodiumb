local sodiumb = require 'lem.sodiumb.core'

local bob = sodiumb.crypto_box_keypair()
for k, v in pairs(bob) do
  print('bob', k, #v)
end

local alice = sodiumb.crypto_box_keypair()
for k, v in pairs(alice) do
  print('alice',k, #v)
end

local nonce = sodiumb.randombytes_buf(sodiumb.crypto_box_NONCEBYTES)
print(#nonce)

local tmsg = ("test "):rep(10)

local msg = sodiumb.crypto_box_easy(tmsg, nonce, bob.publicKey, alice.privateKey)
local dmsg = sodiumb.crypto_box_open_easy(msg, nonce, alice.publicKey, bob.privateKey)

print('dmsg', dmsg)

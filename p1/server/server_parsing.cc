#include <cstring>
#include <iostream>
#include <openssl/rsa.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;

bool is_kblock(vec &block){
  string str(block.begin(),block.begin()+3);
  if(str=="KEY"){
	return true;
  }
  return false;
}

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to send to the client
/// @param storage The Storage object with which clients interact
///
/// @returns true if the server should halt immediately, false otherwise

bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage) {
  //Set up vector with fixed length
  vec len(LEN_RKBLOCK);
  //Read from the client with fixed length
  int read = reliable_get_to_eof_or_n(sd,len.begin(),LEN_RKBLOCK);
  
  //if read is smaller than 256 then return true
  if(read <LEN_RKBLOCK){
     return true;
  }
 
  //Set up decrypt vector with fixed length
  vec decrypt(LEN_RKBLOCK);
  if(is_kblock(len)){
	server_cmd_key(sd, pub);
    return false;
  }
  
  //Decrypt message by RSA
  int dec_byte = RSA_private_decrypt(len.size(),(const unsigned char *)len.data(),decrypt.data(),pri,RSA_PKCS1_OAEP_PADDING);
  if(dec_byte < 0){
	  return false;
  }
  
  //Find the request
  char cmd[3];
  for(int i = 0;  i < 3; i++){
	  cmd[i]=decrypt.at(i);
  }
  string aes = "";
  vec aes_key;
  for(int i = 3; i < 51; i++){
	  aes += decrypt.at(i);
  }
  vec_append(aes_key,aes);
  //Find the length of ablock
  int alen = *(int *)(decrypt.data()+51);
  vec ablock(alen);
  int rb = reliable_get_to_eof_or_n(sd,ablock.begin(),alen);
  if(rb < alen){
	  return true;
  }
  
  //Set up the cipher context for decrypt and encrypt
  EVP_CIPHER_CTX *aes_ctx = create_aes_context(aes_key,false);
  vec ablock_decrypted = aes_crypt_msg(aes_ctx,ablock);
  EVP_CIPHER_CTX *passed_ctx = create_aes_context(aes_key,true);
  
  //Do a for loop to match the request
  vector<string> s= {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(server_cmd_reg) *cmds[] = {server_cmd_reg, server_cmd_bye,
                                      server_cmd_sav, server_cmd_set,
                                      server_cmd_get, server_cmd_all};
	
  for (size_t i = 0; i < s.size(); ++i) {
    if (cmd == s[i]) {
      return cmds[i](sd, storage, passed_ctx, ablock_decrypted);
    }
  }	
  return false;
}

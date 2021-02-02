#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "client_commands.h"

using namespace std;

void send_result_to_file(const vec &buf, const string &filename){
	int length = *((int *)(buf.data()+2));
	std::string str(buf.begin()+6,buf.begin()+6+length);
	/*for(int i = 0; i < length; i++){
		printf("%c",buf.at(6+i));
	}*/
	
	if(!write_file(filename,(const char *)(buf.data()+6),length)){
		printf("error on write file\n");
	}
}

bool check_err_crypto(const vec &v){
	std::string str(v.begin(),v.begin()+2);
	if(str=="OK"){
		return true;
	}else{
		return false;
	}
}

/// client_key() writes a request for the server's key on a socket descriptor.
/// When it gets it, it writes it to a file.
///
/// @param sd      An open socket
/// @param keyfile The name of the file to which the key should be written
void client_key(int sd, const string &keyfile) {
  vec kblock(256,'\0');
  kblock.at(0)='K';
  kblock.at(1)='E';
  kblock.at(2)='Y';
  send_reliably(sd, kblock);
  vec pos;
  pos = reliable_get_to_eof(sd);
  //std::string str(pos.begin(),pos.end());
  unsigned char str[LEN_RSA_PUBKEY];
  for(long unsigned int i = 0; i < LEN_RSA_PUBKEY; i++){
	  str[i]=pos.at(i);
  }
  /*char buf[LEN_RSA_PUBKEY + 1] = {0};
  remain = data.length();
  next_byte = buf;
  while (remain) {
      // NB: recv() with last parameter 0 is the same as read() syscall
      ssize_t rcd = recv(sd, next_byte, remain, 0);
      // NB: as above, 0 bytes received means server closed socket, and -1 means
      //     an error.  EINTR means try again, otherwise we will just crash.
      if (rcd <= 0) {
        if (errno != EINTR) {
          if (rcd == 0) {
            fprintf(stderr, "Error in recv(): EOF\n");
            exit(0);
          } else {
            error_message_and_exit(0, errno, "Error in recv(): ");
          }
        }
      } else {
        next_byte += rcd;
        remain -= rcd;
      }
  }*/
  write_file(keyfile, (char *)str, LEN_RSA_PUBKEY);
  //cerr << "client_key is not implemented\n";
}

/// client_reg() sends the REG command to register a new user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_reg(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_REG);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  reclaim_aes_context(ctx1);
  /*for( long unsigned int i = 0; i < server_dec.size(); i++){
	  
	  printf("%c",server_dec.at(i));
  }*/
  if(check_err_crypto(server_dec)){
	  printf("OK");
  }else{
	  for(long unsigned int i = 0; i < server_dec.size(); i++){
		  printf("%c",server_dec.at(i));
	  }
  }
  //cerr << "client_reg is not implemented\n";
}

/// client_bye() writes a request for the server to exit.
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_bye(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_BYE);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  reclaim_aes_context(ctx1);
  if(check_err_crypto(server_dec)){
	  printf("OK");
  }else{
	  for(long unsigned int i = 0; i < server_dec.size(); i++){
		  printf("%c",server_dec.at(i));
	  }
  }
}

/// client_sav() writes a request for the server to save its contents
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
void client_sav(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_SAV);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  reclaim_aes_context(ctx1);
  for( long unsigned int i = 0; i < server_dec.size(); i++){
	  
	  printf("%c",server_dec.at(i));
  }
  //cerr << "client_sav is not implemented\n";
}

/// client_set() sends the SET command to set the content for a user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void client_set(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &setfile, const string &) {
  vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  vec_append(ablock,setfile.length());
  vec_append(ablock, setfile);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_SET);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  reclaim_aes_context(ctx1);
  for( long unsigned int i = 0; i < server_dec.size(); i++){
	  
	  printf("%c",server_dec.at(i));
  }
  //cerr << "client_set is not implemented\n";
}

/// client_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void client_get(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &getname, const string &) {
  vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  vec_append(ablock,getname.length());
  vec_append(ablock, getname);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_GET);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  //printf("%s \n",server_dec.data()+6);
  reclaim_aes_context(ctx1);
  if(check_err_crypto(server_dec)){
	  printf("OK");
	  //printf(" %s",server_dec.data());
	  int flength = *((int *)(server_dec.data()+2));
	  std::string str(server_dec.begin()+6,server_dec.begin()+6+flength);
	  
	  vec file_name;
	  vec_append(file_name,getname);
	  vec_append(file_name,".file.dat");
	  //printf("%s\n",file_name.data());
	  std::string filename(file_name.begin(),file_name.end());
	  vec content = load_entire_file(str);
	  //std::string content_str(content.begin(),content.end());
	  write_file(filename, (char *)content.data(), content.size());
	  //send_result_to_file(content, filename);
  }else{
	  for(long unsigned int i = 0; i < server_dec.size(); i++){
		  printf("%c",server_dec.at(i));
	  }
  
  }
  
  //send_result_to_file(pos,getname);
  //cerr << "client_get is not implemented\n";
}

/// client_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
/// @param allfile The file where the result should go
void client_all(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &allfile, const string &) {
  vec rblock;
  vec aes_key = create_aes_key();
  int user_length = user.length();
  int pass_length = pass.length();
  vec ablock;
  
  vec_append(ablock,user_length);
  
  vec_append(ablock,user);
  
  vec_append(ablock,pass_length);
  vec_append(ablock,pass);
  vec_append(ablock,allfile.length());
  vec_append(ablock, allfile);
  
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, true);
  vec ablock_enc= aes_crypt_msg(ctx, ablock);
  if(!reset_aes_context(ctx,aes_key,false)){
	  printf("err in reset\n");
  }
  
  
  int ablock_enc_size = ablock_enc.size();
  //Set the name first
  vec_append(rblock,REQ_ALL);
  vec_append(rblock,aes_key);
  vec_append(rblock,ablock_enc_size);
  
  //store encrypted rblock with RSA public key
  vec rblock_dec(RSA_size(pubkey));
  RSA_public_encrypt(rblock.size(),rblock.data(),rblock_dec.data(),pubkey,RSA_PKCS1_OAEP_PADDING);
  
  vec block;
  vec_append(block,rblock_dec);
  vec_append(block,ablock_enc);
  send_reliably(sd, rblock_dec);
  
  send_reliably(sd, ablock_enc);
  vec pos=reliable_get_to_eof(sd);
  
  reclaim_aes_context(ctx);
  EVP_CIPHER_CTX *ctx1 = create_aes_context(aes_key, false);
  vec server_dec = aes_crypt_msg(ctx1, pos);
  reclaim_aes_context(ctx1);
  if(check_err_crypto(server_dec)){
	  printf("OK");
	  /*int flength = *((int *)(server_dec.data()+2));
	  std::string str(server_dec.begin()+6,server_dec.begin()+6+flength);
	  
	  
	  vec file_name;
	  vec_append(file_name,allfile);
	  vec_append(file_name,".dat");
	  //printf("%s\n",file_name.data());
	  std::string filename(file_name.begin(),file_name.end());
	  vec content = load_entire_file(str);*/
	  //std::string content_str(content.begin(),content.end());
	  send_result_to_file(server_dec, allfile);
  }else{
	  printf("%s",server_dec.data());
  }
  //send_result_to_file(pos,allfile);
  //cerr << "client_all is not implemented\n";
}


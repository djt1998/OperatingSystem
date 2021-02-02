#include <string>

#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_storage.h"

using namespace std;

string parse_name(const vec &req){
	//printf("name\n");
	string username;
	int ulen = *(int *)(req.data());
	username = string(req.data()+4,req.data()+4+ulen);
	
	return username;
}
string parse_pass(const vec &req){
	//printf("pass\n");
	string password;
	int ulen = *(int *)(req.data());
	int plen = *(int *)(req.data()+4+ulen);
	password = string(req.data()+8+ulen,req.data()+8+ulen+plen);
	
	return password;
}
vec parse_content(const vec &req){
	//printf("conetent\n");
	int ulen = *(int *)(req.data());
	int plen = *(int *)(req.data()+4+ulen);
	int clen = *(int *)(req.data()+plen+ulen+8);
	vec content;
	content.insert(content.begin(),req.begin()+ulen+plen+12,req.begin()+ulen+plen+12+clen);
	//printf("Content size %ld\n",content.size());
	return content;
}

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //All user name info
  //vec content;
  /*string name = parse_name(req);
  string pass = parse_pass(req);
  pair<bool,vec> names = storage.get_all_users(name,pass);
  if(names.first){
    vec msg = aes_crypt_msg(ctx,names.second);
    if(send_reliably(sd,msg)){
      return true;
    }
  }
	printf("false yaa\n");
  return false;*/
	int num_user = *(int *)req.data();
    string user = "";
    for(int i = 4; i < num_user+4; i++){
        user += req.at(i);
    }
    int num_pass = *(int *)(req.data()+4+num_user);
    string pass ="";
    for(int i= 8+num_user; i < 8+num_user+num_pass;i++){
        pass += req.at(i);
    }
    pair<bool,vec> result = storage.get_all_users(user,pass);

    vec recd_content = result.second;
    //cout <<"rec content size: "<< recd_content.size() <<endl;
    //concat the response block 
    vec response; 
    //add okay 
    vec_append(response,RES_OK);
    //add length 
    vec len_c(1);
    vec_append(len_c, recd_content.size());
    len_c.erase(len_c.begin());
    //add length to okay 
    vec_append(response, len_c);
    //finally add content 
    vec_append(response, recd_content);
    //cout << "final block size: "<< response.size()<<endl;
    vec enc_block = aes_crypt_msg(ctx,response);
    //cout << "enc_block size"<< enc_block.size() <<endl;
    //send to client
    send_reliably(sd, enc_block);
    return false;
}

/// Respond to a SET command by putting the provided req into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //vec content;
  string name = parse_name(req);
  string pass = parse_pass(req);
  vec content = parse_content(req);
  vec temp;
  vec_append(temp,pass);
  printf("Content %s and content1 %s\n",temp.data(),content.data());
  if(storage.auth(name,pass)){
    vec result = storage.set_user_data(name,pass,content);
    vec msg = aes_crypt_msg(ctx,result);
	printf("result is %s\n",msg.data());
    send_reliably(sd,msg);
    //printf("Result is what %s\n",result.data());
	//cerr << RES_OK;
	printf("You are here !!!!");
    return false;
  }
  printf("It returns false\n");
  return false;
}

/// Respond to a GET command by getting the req for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,const vec &req) {

  string name = parse_name(req);
  string pass = parse_pass(req);
  vec content = parse_content(req);
  string str(content.begin(),content.end());
  
  pair<bool,vec> result = storage.get_user_data(name,pass,str);
  vec recd_content = result.second;
  //printf("recd content %s\n",recd_content.data());
  //vec temp;
  //temp.insert(temp.begin(),recd_content.begin()+2,recd_content.end());
  //vec response;
  //vec_append(response,RES_OK);
  //vec len_c(1);
  //vec_append(response,temp.size());
  //len_c.erase(len_c.begin());
  //vec_append(response,);
  //vec_append(response,recd_content);
  //printf("Response %s\n",recd_content.data()+6);
  vec enc_block = aes_crypt_msg(ctx,recd_content);
  send_reliably(sd,enc_block);
  return false;
  //printf("First %s\n",content_info.second.at(0).data);
  /*if(content_info.first){
    vec msg = aes_crypt_msg(ctx,content_info.second);
    if(send_reliably(sd,msg)){
		printf("we can send\n");
      cerr << RES_OK;
      return false;
    }
	printf("In one if but cannot send \n");
  }
  printf("False at final\n");
  return false;*/
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  
  //vec content;
  string name = parse_name(req);
  string pass = parse_pass(req);
  
  if(storage.add_user(name,pass)){
    vec msg = aes_crypt_msg(ctx,RES_OK);
	//printf("Inside ref\n");
    send_reliably(sd,msg);
    return false;
  }
  vec msg = aes_crypt_msg(ctx,RES_ERR_USER_EXISTS);
  send_reliably(sd,msg);
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
void server_cmd_key(int sd, const vec &pubfile) {
  printf("Being here\n");
  if(!send_reliably(sd, pubfile)){

  }
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns true, to indicate that the server should stop, or false on an error
bool server_cmd_bye(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //vec content;
  string name = parse_name(req);
  string pass = parse_pass(req);
  if(storage.auth(name,pass)){
    vec msg = aes_crypt_msg(ctx,RES_OK);
    send_reliably(sd,msg);
    return true;
  }
  return false;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_sav(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //vec content;
  string name = parse_name(req);
  string pass = parse_pass(req);
  if(storage.auth(name,pass)){
    //storage.shutdown();
    storage.persist();
	vec msg = aes_crypt_msg(ctx,RES_OK);
	send_reliably(sd,msg);
    return false;
  }
  return false;
}




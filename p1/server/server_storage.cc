#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>
#include <stdio.h>
#include <fstream>
#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"
#include<string.h>
#include "server_storage.h"
#include <stdint.h>

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  ///
  /// NB: this isn't needed in assignment 1, but will be useful for backwards
  ///     compatibility later on.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// The map of authentication information, indexed by username
  unordered_map<string, AuthTableEntry> auth_table;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename
  ///
  /// @param fname The name of the file that should be used to load/store the
  ///              data
  Internal(const string &fname) : filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname The name of the file that should be used to load/store the
///              data
Storage::Storage(const string &fname) : fields(new Internal(fname)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading an auth_table from this.filename.
/// Note that load() begins by clearing the auth_table, so that when the call
/// is complete, exactly and only the contents of the file are in the
/// auth_table.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
// 
bool Storage::load() {
  

  //Clean the table 

  this -> fields -> auth_table.clear();

  FILE *file;
  file = fopen((this -> fields -> filename).c_str(),"rb");
  if(file == NULL){
    cerr << "File not found: " << this->fields->filename<< endl;
    return true;
  }
  else{

    file = NULL;
    vec data = load_entire_file(this -> fields -> filename);

    int counter = 0;
    //int counter1 = 0;
    //A while loop to read the file 
    while(counter < int(data.size())){
      //Read the first 8 bytes
      auto begin = data.begin()+counter;
      counter += 8;
      auto end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec binary(begin,end);
      if(binary != vec_from_string("AUTHAUTH")){
        return false;
      }

      //Read the length of username
      begin = data.begin()+counter;
      counter += 4;
      end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec name_length(begin,end);
      //Vector.data() return A pointer to the first element same as at(0)
      //int name_len = atoi((char*)name_length.data());
      int name_len = *(int*)name_length.data();

      //Read the user name
      begin = data.begin()+counter;
      counter += name_len;
      end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec username_vec(begin,end);
      string username;
      username = string(username_vec.begin(),username_vec.end());
      // int count = 0;
      // while(count != name_len){
      //   username.append(reinterpret_cast<char*>(username_vec[count]));
      //   count += 1;
      // }

      //Read the passward length 
      begin = data.begin()+counter;
      counter += 4;
      end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec pass_length(begin,end);
      //Vector.data() return A pointer to the first element same as at(0)
      //int pass_len = atoi((char*)pass_length.data());
      int pass_len = *(int*)pass_length.data();

      //Read the user name
      begin = data.begin()+counter;
      counter += pass_len;
      end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec pass_vec(begin,end);
      string pass_hash;
      pass_hash = string(pass_vec.begin(),pass_vec.end());
      // count = 0;
      // while(count != pass_len){
      //   pass_hash.append(reinterpret_cast<char*>(pass_vec[count]));
      //   count += 1;
      // }

      //Read the content length 
      begin = data.begin()+counter;
      counter += 4;
      end = data.begin()+counter;
      //In vector package, we can create the vector in range in [first,last) iterator
      vec bytes(begin,end);
      //Vector.data() return A pointer to the first element same as at(0)
      //int num_bytes = atoi((char*)bytes.data());
      int num_bytes = *(int*)bytes.data();

      //Read the content
      
      Internal::AuthTableEntry toAdd = {username,pass_hash};
      this->fields->auth_table.insert({username,toAdd});
      if(num_bytes != 0){
        begin = data.begin()+counter;
        counter += num_bytes;
        end = data.begin()+counter;
        vec content(begin,end);
        this->fields->auth_table.at(username).content = content;
      }
      //In vector package, we can create the vector in range in [first,last) iterator
      //vec content(begin,end);

      // counter1 = counter;
      // begin = data.begin()+counter1;
      // counter1 += 8;
      // end = data.end()+counter1;
      // //In vector package, we can create the vector in range in [first,last) iterator
      // vec binary_check(begin,end);
      // if(binary_check != vec_from_string("AUTHAUTH")){
      //   return false;
      // }
      //this->fields->auth_table[username] = {username,pass_hash,content};
      
      // Internal::AuthTableEntry toAdd = {username,pass_hash,content};
      // this->fields->auth_table.insert(username,toAdd);
      
    }
    cout << "Loaded: " << this->fields->filename;
    fclose(file);
    return true;
  }
  fclose(file);
  return false;
}



/// Create a new entry in the Auth table.  If the user_name already exists, we
/// should return an error.  Otherwise, hash the password, and then save an
/// entry with the username, hashed password, and a zero-byte content.
///
/// @param user_name The user name to register
/// @param pass      The password to associate with that user name
///
/// @returns False if the username already exists, true otherwise
bool Storage::add_user(const string &user_name, const string &pass) {
  
  auto it = this->fields->auth_table.begin();
  while(it != this->fields->auth_table.end()){
      if(it->first == user_name){
		  //cerr<<RES_ERR_USER_EXISTS;
          return false;
	  }
      it++;
  }
  Internal::AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = pass;
  this->fields->auth_table.insert({user_name,entry});
  return true;
  
}

/// Set the data bytes for a user, but do so if and only if the password
/// matches
///
/// @param user_name The name of the user whose content is being set
/// @param pass      The password for the user, used to authenticate
/// @param content   The data to set for this user
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
vec Storage::set_user_data(const string &user_name, const string &pass,const vec &content) {

  /*if(auth(user_name,pass)){
    auto check = this->fields->auth_table.find(user_name);
    check -> second.content = content;
      // vec result = vec_from_string(RES_OK);
      // int length = this->fields->filename.length();
      // // string len = to_string(length);
      // vec_append(result,length);
      // string file = this->fields->filename;
      // for(int i = 0; i < length; ++i){
      //   vec_append(result,file.at(i));
      // }
      return vec_from_string(RES_OK);
  }
  return vec_from_string(RES_ERR_LOGIN);*/
  vec msg;
  printf("content %s\n",content.data());
    auto it = this->fields->auth_table.begin();
    while(it != this->fields->auth_table.end()){
        if(it->first == user_name){
            if((it->second).pass_hash == pass){
                (it->second).content = content;
                vec_append(msg,RES_OK);
                return msg;
            }
            else{
                vec_append(msg,RES_ERR_LOGIN);
                return msg;
            }


        }
        it++;

    }
    vec_append(msg,RES_ERR_LOGIN);
    return msg;
}

/// Return a copy of the user data for a user, but do so only if the password
/// matches
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param who       The name of the user whose content is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.  Note that "no data" is an error
pair<bool, vec> Storage::get_user_data(const string &user_name,const string &pass, const string &who) {
  
    vec msg;
    bool who_exist;
    bool user_valid;
    vec content_who;
    auto it = this->fields->auth_table.begin();
    while(it != this->fields->auth_table.end()){
        if(it->first == who){
            who_exist = true;
            content_who = (it->second).content;
        }
        if(it->first == user_name){
            if((it->second).pass_hash == pass){
                user_valid = true;
            }

        }

        if(who_exist && user_valid)
            break;
        it++;

    }
    if(user_valid){
        if(who_exist){
            if(content_who.size() != 0) {
                vec_append(msg,RES_OK);
                vec_append(msg,content_who.size());
                vec_append(msg,content_who);
                return {true,msg};
            }
            else{
                vec_append(msg,RES_ERR_NO_DATA);
                return{false,msg};
            }
        }
        else{
            vec_append(msg,RES_ERR_NO_USER);
            return {false,msg};
        }

    }
    else{
        vec_append(msg,RES_ERR_LOGIN);
        return {false,msg};
    }
  /*if(auth(user_name,pass)){
    auto user = this->fields->auth_table.find(who);
    if(user != this->fields->auth_table.end()) {
      return {true,user->second.content};
    }
    else{
      return {false,vec_from_string(RES_ERR_NO_USER)};
    }
  }
  else{
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }


  return {true, vec_from_string(RES_ERR_NO_DATA)};*/
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,const string &pass) {
  
  /*if(auth(user_name,pass)){
    vec usernames;
    string new_line = "\n";
    for(auto& i:this->fields->auth_table){
      int len = (i.first).length();
      string name = i.first;
      for(int m = 0; m < len; m++){
        vec_append(usernames,name.at(m));
      }
      vec_append(usernames,new_line.c_str());
    } 
    
    return {true,usernames};
  }

  return {false,vec_from_string(RES_ERR_LOGIN)};*/
    vec msg;
    vec userlist; //hold user list 
    string name;
    //first verify user 
    if (!(auth(user_name, pass))){
        //invalid login
        vec_append(msg,RES_ERR_LOGIN);
        return {false, msg};
    }
    // loop through the auth_table
    for(auto it = ((this->fields->auth_table)).begin(); it != ((this->fields->auth_table)).end(); ++it){
        name = (it->second).username;
        //cout << "name: "<<name <<endl;
        name +="\n";
        vec_append(userlist,name);
    }
    return {true, userlist};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {
  
  auto it = this->fields->auth_table.begin();
  while(it != this->fields->auth_table.end()){
      if(it->first == user_name){
          if((it->second).pass_hash== pass){
              return true;
          }
          else
              return false;
      }
      it++;
  }
  return false;
  /*auto check = this->fields->auth_table.find(user_name);
  //Check if the username is in the map
  if(this->fields->auth_table.find(user_name) == this->fields->auth_table.end()){
    //cerr << RES_ERR_USER_EXISTS;
    return false;
  }
  else{
    // Hash the passward
    unsigned char hash[16];
    MD5((unsigned char*)pass.c_str(),pass.length(),hash);
    string passward = check -> second.pass_hash;
    // string pwd(reinterpret_cast< char const* >(hash));
    string pwd = string((const char*)hash);
    // unsigned char digest[16];
    // MDX_CTX ctx;
    // MD5_Init(&ctx);
    // MD5_Update(&ctx,(void*)pass.c_str(),pass.length());
    // MD5_Final(digest,&ctx);
    // string pwd = string(digest,digest+16);
    //string pwd =string((const char*)hash);
    // for(int i = 0; i < hash.length; ++i){
    //   pwd.append(reinterpret_cast<const char*>(hash[i]));
    // }
    // if(strcmp(pwd.c_str(),passward.c_str()) == 0){
    //   //cerr << RES_OK;
    //   return true;
    // }
    if((pwd.compare(passward)) == 0){
      //cerr << RES_OK;
      return true;
    }


    else{
      //cerr <<RES_ERR_LOGIN;
      return false;
    }
  
  }
  
  return false;*/
}

/// Write the entire Storage object (right now just the Auth table) to the
/// file specified by this.filename.  To ensure durability, Storage must be
/// persisted in two steps.  First, it must be written to a temporary file
/// (this.filename.this->fields->filename).  Then the temporary file can be renamed to replace
/// the older version of the Storage object.
void Storage::persist() { 

  string tmpfile = fields->filename + ".tmp";
  // start writing to file
  // ofstream file_obj; 
  // file_obj.open(tmpfile, ios::app); 

  vec all_user = vec_from_string("");
  for(auto elem : (fields->auth_table)){
    vec_append(all_user,"AUTHAUTH");
    string username = (elem.second).username;
    vec_append(all_user,int(username.size()));
    vec_append(all_user,username);           
    string pwd = (elem.second).pass_hash; 
    vec_append(all_user,int(pwd.size()));
    vec_append(all_user,pwd);     
    vec content  = (elem.second).content;
    vec_append(all_user,int(content.size()));
    vec_append(all_user,content);        
  }
  int num_bytes = all_user.size(); 
  if(num_bytes > 0){   // write to file
    
    write_file(tmpfile,(char*)all_user.data(),num_bytes);
  }
  rename(tmpfile.c_str(), (fields->filename).c_str());
  }

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}

#include <cstdio>
#include <iostream>
#include <openssl/md5.h>
#include <unistd.h>
#include <unordered_map>
#include <cstring>
#include <fstream>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
#include "../common/mru.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"

#include "server_authtableentry.h"
#include "server_persist.h"
#include "server_quotas.h"
#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const string KVENTRY = "KVKVKVKV";

  /// A unique 8-byte code for incremental persistence of changes to the auth
  /// table
  inline static const string AUTHDIFF = "AUTHDIFF";

  /// A unique 8-byte code for incremental persistence of updates to the kv
  /// store
  inline static const string KVUPDATE = "KVUPDATE";

  /// A unique 8-byte code for incremental persistence of deletes to the kv
  /// store
  inline static const string KVDELETE = "KVDELETE";
  

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// The open file
  FILE *storage_file = nullptr;

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The MRU table for tracking the most recently used keys
  mru_manager mru;

  /// A table for tracking quotas
  ConcurrentHashTable<string, Quotas*> quota_table;

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(string fname, size_t num_buckets, size_t upq, size_t dnq, size_t rqq,
           double qd, size_t top)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname),
        up_quota(upq), down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(top),
        quota_table(num_buckets) {}

  // NB: You may want to add a function here for interacting with the quota
  // table to check a user's quota
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname       The name of the file that should be used to load/store
///                    the data
/// @param num_buckets The number of buckets for the hash
Storage::Storage(const string &fname, size_t num_buckets, size_t upq,
                 size_t dnq, size_t rqq, double qd, size_t top)
    : fields(new Internal(fname, num_buckets, upq, dnq, rqq, qd, top)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

int bti(const unsigned char *arr)
{
  return int(arr[3] << 24 | arr[2] << 16 | arr[1] << 8 | arr[0]);
}

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete,
/// exactly and only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {
  if (!(file_exists(fields->filename)))
  {
    cerr << "File not found: " << fields->filename << endl;
    fields ->storage_file = fopen((fields->filename).c_str(),"a");
    return true;
  }
  vec fv = load_entire_file(fields->filename);
  fields -> storage_file = fopen((fields->filename).c_str(),"a");
  

  fields->auth_table.clear();
  fields->kv_store.clear();
  fields->mru.clear();

  auto iterator = fv.begin();
  while (iterator != fv.end())
  {
    string str(iterator, iterator + 8);
    iterator += 8;

    if (str == fields->AUTHENTRY)
    {
      string user_length(iterator, iterator + 4);
      int username_length = bti((unsigned char *)user_length.c_str());
      iterator += 4;
      string username(iterator, iterator + username_length);
      iterator += username_length;

      string pass_hash_length_str(iterator, iterator + 4);
      int pass_hash_length = bti((unsigned char *)pass_hash_length_str.c_str());
      iterator += 4;
      string pass_hash(iterator, iterator + pass_hash_length);
      iterator += pass_hash_length;

      string content_length_str(iterator, iterator + 4);
      int content_length = bti((unsigned char *)content_length_str.c_str());
      iterator += 4;
      string content(iterator, iterator + content_length);
      iterator += content_length;

      /*Storage::Internal::AuthTableEntry new_entry;
      auto f = [](){};
      new_entry.username = username;
      new_entry.pass_hash = pass_hash;
      new_entry.content = vec_from_string(content);*/
      //fields ->auth_table.insert(username,new_entry,f);
      //fields->auth_table.insert(username, new_entry);
	  
	  //quota_tracker *q1 = new quota_tracker(this->fields->up_quota, this->fields->quota_dur);
      //quota_tracker *q2 = new quota_tracker(this->fields->down_quota, this->fields->quota_dur);
      //quota_tracker *q3 = new quota_tracker(this->fields->req_quota, this->fields->quota_dur);
	  AuthTableEntry new_user = {username, pass_hash, vec_from_string(content)};
	  //Quotas new_quota = {*q1, *q2, *q3};
	  //quota_tracker x;
	  //quota_tracker x = quota_tracker(this->fields->up_quota, this->fields->quota_dur);
	  //quota_tracker y(this->fields->down_quota, this->fields->quota_dur);
	  //quota_tracker z(this->fields->req_quota, this->fields->quota_dur);
	  Quotas* new_quota=new Quotas({quota_tracker(this->fields->up_quota, this->fields->quota_dur), quota_tracker(this->fields->down_quota, this->fields->quota_dur), quota_tracker(this->fields->req_quota, this->fields->quota_dur)});
	  this->fields->auth_table.insert(username.c_str(),new_user,[](){});
	  this->fields->quota_table.insert(username.c_str(),new_quota, [](){});
    }
    else if (str == fields->KVENTRY)
    {
      string keystr(iterator, iterator + 4);
      int key_len = bti((unsigned char *)keystr.c_str());
      iterator += 4;
      string key(iterator, iterator + key_len);
      iterator += key_len;

      string valstr(iterator, iterator + 4);
      int value_len = bti((unsigned char *)valstr.c_str());
      iterator += 4;
      string value(iterator, iterator + value_len);
      iterator += value_len;
      auto f = [](){};
      fields->kv_store.insert(key, vec_from_string(value),f);
    }
    else if(str == fields->AUTHDIFF)
    {
      string user_length(iterator, iterator + 4);
      int username_length = bti((unsigned char *)user_length.c_str());
      iterator += 4;
      string username(iterator, iterator + username_length);
      iterator += username_length;

      string content_length_str(iterator, iterator + 4);
      int content_length = bti((unsigned char *)content_length_str.c_str());
      iterator += 4;
      string content(iterator, iterator + content_length);
      iterator += content_length;
      auto f = [&](AuthTableEntry &add){
        add.content = vec_from_string(content);
      };
      fields ->auth_table.do_with(username,f);
    }
    else if(str == fields->KVUPDATE){
      string keystr(iterator, iterator + 4);
      int key_len = bti((unsigned char *)keystr.c_str());
      iterator += 4;
      string key(iterator, iterator + key_len);
      iterator += key_len;

      string valstr(iterator, iterator + 4);
      int value_len = bti((unsigned char *)valstr.c_str());
      iterator += 4;
      string value(iterator, iterator + value_len);
      iterator += value_len;
      auto f = [](){};
      fields->kv_store.upsert(key,vec_from_string(value),f,f);
    }
    else if(str == fields->KVDELETE){
      string keystr(iterator, iterator + 4);
      int key_len = bti((unsigned char *)keystr.c_str());
      iterator += 4;
      string key(iterator, iterator + key_len);
      iterator += key_len;
      auto f = [](){};
      fields ->kv_store.remove(key,f);
    }
  }

  cerr << "Loaded: " << fields->filename << endl;
  
  return true;
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
    
	//new_Add.username = user_name;
	unsigned char passhashed[16];
    MD5((unsigned char *)pass.c_str(), pass.length(), passhashed);
  string pass_h = string((char *)passhashed, 16);
	//new_Add.pass_hash = pass_h;
	AuthTableEntry new_Add={user_name, pass_h, vec()}; 
	Quotas* new_quota = new Quotas({quota_tracker(this->fields->up_quota, this->fields->quota_dur),
  quota_tracker(this->fields->down_quota, this->fields->quota_dur), quota_tracker(this->fields->req_quota, this->fields->quota_dur)});
	std::function<void(AuthTableEntry)> f = [=](AuthTableEntry add){return;};
	//cout<<"zhe li?"<<endl;
	if(fields->auth_table.do_with_readonly(user_name,f)){
		//cout<<RES_ERR_NO_USER<<endl;
		return false;
	}else{
    //A lambda function to write the data into disk if success
    auto f1 = [&](){
      vec data;
      vec_append(data, fields->AUTHENTRY);
      vec_append(data, user_name.size());
      vec_append(data, user_name);
      vec_append(data, pass_h.size());
      vec_append(data, pass_h);
      vec_append(data, 0);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file); //Write into file
      fflush(fields->storage_file); 
      fsync(fileno(fields->storage_file));//Write into disk
    };
		fields->auth_table.insert(user_name,new_Add,f1);
		fields->quota_table.insert(user_name,new_quota,[](){});
		//cout<<"OK"<<endl;
		return true;
	
	}
	
	return false;
  
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
vec Storage::set_user_data(const string &user_name, const string &pass,
                           const vec &content) {
  bool temp=false;
	unsigned char passhashed[16];
  MD5((unsigned char *)pass.c_str(), pass.length(), passhashed);
	//std::string pass_encry = string((char *)passhashed, 16);
	std::function<void(const AuthTableEntry&)> f = [&temp,passhashed](const AuthTableEntry &add){if(strncmp((const char*)passhashed, add.pass_hash.c_str(), 16)==0){temp=true;return;}else{temp=false;return;}return;};
	bool username_match = fields->auth_table.do_with_readonly(user_name,f);
	if(temp==false||username_match==false){
		cout<<"Wrong password or username"<<endl;
		vec result;
		vec_append(result,false);
		vec_append(result,RES_ERR_NO_DATA);
		return result;
	}else{
    //A lambda function to write the data into disk if success
		std::function<void(AuthTableEntry&)> f1 = [&](AuthTableEntry &add){
      add.content=content;
      vec data;
      vec_append(data,fields->AUTHDIFF);
      vec_append(data, user_name.size());
      vec_append(data, user_name);
      vec_append(data, content.size());
      vec_append(data,content);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file);
      fflush(fields->storage_file);
      fsync(fileno(fields->storage_file));
      cout << data.size();
      };
		fields->auth_table.do_with(user_name, f1);
		vec result;
		//vec_append(result,true);
		vec_append(result,RES_OK);
		//cout<<"OK"<<endl;
		return result;		
	}
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
pair<bool, vec> Storage::get_user_data(const string &user_name,
                                       const string &pass, const string &who) {
  bool temp=false;
  unsigned char passhashed[16];
  MD5((unsigned char *)pass.c_str(), pass.length(), passhashed);
  //std::string pass_encry = string((char *)passhashed, 16);
  std::function<void(const AuthTableEntry&)> f = [&temp,passhashed](const AuthTableEntry &add){if(strncmp((const char*)passhashed, add.pass_hash.c_str(), 16)==0){temp=true;return;}else{temp=false;return;}return;};
  bool username_match = fields->auth_table.do_with_readonly(user_name,f);
  if(temp==false||username_match==false){
	cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return {true, result};
  }else{
	vec content;
	std::function<void(const AuthTableEntry&)> f1 = [&content](const AuthTableEntry &add){content=add.content;return;};
	
	if(fields->auth_table.do_with(who,f1)){
		if(content.size()==0){
			vec errmsg;
			vec_append(errmsg,RES_ERR_NO_DATA);
			return {true, errmsg};
		}
		//vec result;
		//vec_append(result,RES_OK);
		//vec_append(result,content);
		return {false, content};
	}else{
		cout<<"Username does not exists"<<endl;
		vec result;
		vec_append(result, RES_ERR_LOGIN);
		return {true, result};
	}
  }
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass) {
  bool temp=false;
  unsigned char passhashed[16];
  MD5((unsigned char *)pass.c_str(), pass.length(), passhashed);
  //std::string pass_encry = string((char *)passhashed, 16);
  std::function<void(AuthTableEntry)> f = [&temp,passhashed](AuthTableEntry add){if(strncmp((const char*)passhashed, add.pass_hash.c_str(), 16)==0){temp=true;return;}else{temp=false;return;}return;};
  bool username_match = fields->auth_table.do_with_readonly(user_name,f);
  if(temp==false||username_match==false){
	cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return {true, result};
  }else{
	vec content;
	std::function<void()> then=[](){return;};
	std::function<void(string, AuthTableEntry)> f1 = [&content](string name, AuthTableEntry add){
		vec_append(content,add.username);
		vec_append(content,"\n");
		return;};
	fields->auth_table.do_all_readonly(f1,then);
	return {false, content};
  }
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {

  bool temp=false;
  unsigned char passhashed[16];
  MD5((unsigned char *)pass.c_str(), pass.length(), passhashed);
  //std::string pass_encry = string((char *)passhashed, 16);
  std::function<void(AuthTableEntry)> f = [&temp,passhashed](AuthTableEntry add){if(strncmp((const char*)passhashed, add.pass_hash.c_str(), 16)==0){temp=true;return;}else{temp=false;return;}return;};
  bool username_match = fields->auth_table.do_with_readonly(user_name,f);
  bool result = temp||username_match;
  return result;
  
}

/// Write the entire Storage object to the file specified by this.filename.
/// To ensure durability, Storage must be persisted in two steps.  First, it
/// must be written to a temporary file (this.filename.tmp).  Then the
/// temporary file can be renamed to replace the older version of the Storage
/// object.
void Storage::persist() {
	auto tmp_filename = fields->filename + ".tmp";
  vec data;

  fields->auth_table.do_all_readonly([&](const string key, const AuthTableEntry &value) {
    vec_append(data, fields->AUTHENTRY);
    vec_append(data, value.username.size());
    vec_append(data, value.username);
    vec_append(data, value.pass_hash.size());
    vec_append(data, value.pass_hash);
    vec_append(data, value.content.size());
    vec_append(data, value.content); }, [&]() {
      fields->kv_store.do_all_readonly([&](const string key, const vec &value) {
      vec_append(data, fields->KVENTRY);
      vec_append(data, key.size());
      vec_append(data, key);
      vec_append(data, value.size());
      vec_append(data, value); }, [&]() {
        //write to file
        fclose(fields->storage_file);
        write_file(tmp_filename, reinterpret_cast<const char *>(data.data()), data.size());
        rename(tmp_filename.c_str(), fields->filename.c_str());
        fields ->storage_file = fopen((fields->filename).c_str(),"a");
      });
    });
}

/// Create a new key/value mapping in the table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being created
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message
vec Storage::kv_insert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {

  if(!auth(user_name,pass)){
	//cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return result;
  }else{
	  vec res;
  this->fields->quota_table.do_with(user_name, [&](Quotas* entry){
    if(!entry->requests.check(1)) {
      res = vec_from_string(RES_ERR_QUOTA_REQ);
      return;
    } else {
      entry->requests.add(1);
    } 
    if(!entry->uploads.check(val.size())) {
      res = vec_from_string(RES_ERR_QUOTA_UP);
    } else {
      entry->uploads.add(val.size());
    }
  });
  if(res.size()){
	  return res;
  }

    //A lambda function to write the data into disk if success
  auto f = [&](){
	  this->fields->mru.insert(key);
      vec data;
      vec_append(data, fields->KVENTRY);
      vec_append(data, key.size());
      vec_append(data, key);
      vec_append(data, val.size());
      vec_append(data, val);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file);
      fflush(fields->storage_file);
      fsync(fileno(fields->storage_file));
    };
	if(fields->kv_store.insert(key,val,f)){
		vec result;
		vec_append(result,RES_OK);
		//fields->mru.insert(key);
		return result;
	}
	else{
		vec result;
		vec_append(result,RES_ERR_KEY);
		return result;
	}
	
  }
  return vec_from_string(RES_ERR_NO_DATA);
};

/// Get a copy of the value to which a key is mapped
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.
pair<bool, vec> Storage::kv_get(const string &user_name, const string &pass,
                                const string &key) {
  if(!auth(user_name,pass)){
	cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return {true, result};
  }else{
	  vec res;
	  this->fields->quota_table.do_with(user_name, [&](Quotas* entry){
		if(!entry->requests.check(1)) {
			res = vec_from_string(RES_ERR_QUOTA_REQ);
		} else {
			entry->requests.add(1);
		}
		if(!this->fields->kv_store.do_with(key, [&](const vec value) {
			if(!entry->requests.check(1)) {
				res = vec_from_string(RES_ERR_QUOTA_REQ);
			}else{
			if(!entry->downloads.check(value.size())) {
				res = vec_from_string(RES_ERR_QUOTA_DOWN);
			} else {
				entry->downloads.add(value.size());
			}
			}
		})) res = vec_from_string(RES_ERR_KEY);
	  });
	if(res.size()) {
		return {true, res};
	}
	vec value;
	
	
	
    if(!this->fields->kv_store.do_with_readonly(key, [&](const vec content){
          this->fields->mru.insert(key);
          vec_append(value, content);})
      )
    {
      return {true, vec_from_string(RES_ERR_KEY)};
    }
  
	return {false, value};
 
  }
  return {true, vec_from_string(RES_ERR_NO_DATA)};
};

/// Delete a key/value mapping
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being deleted
///
/// @returns A vec with the result message
vec Storage::kv_delete(const string &user_name, const string &pass,
                       const string &key) {
  if(!auth(user_name,pass)){
	cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return result;
  }else{
	  vec res;
  this->fields->quota_table.do_with(user_name, [&](Quotas* entry){
    if(!entry->requests.check(1)) {
      res = vec_from_string(RES_ERR_QUOTA_REQ);
    } else {
      entry->requests.add(1);
    }
  });
  if(res.size()){
	  return res;
  }
    //A lambda function to write the data into disk if success
  auto f = [&](){
      vec data;
      vec_append(data, fields->KVDELETE);
      vec_append(data, key.size());
      vec_append(data, key);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file);
      fflush(fields->storage_file);
      fsync(fileno(fields->storage_file));
    };
	if(fields->kv_store.remove(key,f)){
		vec result;
		vec_append(result,RES_OK);
		fields->mru.remove(key);
		return result;
	}else{
		vec result;
		vec_append(result,RES_ERR_NO_DATA);
		return result;
	}
  }
  return vec_from_string(RES_ERR_NO_DATA);
  
};



/// Insert or update, so that the given key is mapped to the give value
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being upserted
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message.  Note that there are two "OK"
///          messages, depending on whether we get an insert or an update.
vec Storage::kv_upsert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {

  if(!auth(user_name,pass)){
	cout<<"Wrong password or username"<<endl;
	vec result;
	vec_append(result,RES_ERR_LOGIN);
	return result;
  }else{
	  vec res;
  this->fields->quota_table.do_with(user_name, [&](Quotas* entry){

    if(!entry->requests.check(1)) {
      res = vec_from_string(RES_ERR_QUOTA_REQ);
    } else if(!entry->uploads.check(val.size())) {
      entry->requests.add(1);
      res = vec_from_string(RES_ERR_QUOTA_UP);
    } else {
      entry->requests.add(1);
      entry->uploads.add(val.size());
    }
  });
  if(res.size()){
	  return res;
  }
    //A lambda function to write the data into disk if success
  auto f = [&](){
      vec data;
      vec_append(data, fields->KVENTRY);
      vec_append(data, key.size());
      vec_append(data, key);
      vec_append(data, val.size());
      vec_append(data, val);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file);
      fflush(fields->storage_file);
      fsync(fileno(fields->storage_file));
    };
  
  auto f1 = [&](){
      vec data;
      vec_append(data, fields->KVUPDATE);
      vec_append(data, key.size());
      vec_append(data, key);
      vec_append(data, val.size());
      vec_append(data, val);
      fwrite(reinterpret_cast<const char *>(data.data()),sizeof(char),data.size(),fields->storage_file);
      fflush(fields->storage_file);
      fsync(fileno(fields->storage_file));
    };
	if(fields->kv_store.upsert(key,val,f,f1)){
		fields->mru.insert(key);
		return vec_from_string(RES_OKINS);
	}else{
		return vec_from_string(RES_OKUPD);
	}
  }
  return vec_from_string(RES_ERR_NO_DATA);
  
};

/// Return all of the keys in the kv_store, as a "\n"-delimited string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_all(const string &user_name, const string &pass) {
  if(!auth(user_name,pass)){
		cout<<"Wrong password or username"<<endl;
		vec result;
		vec_append(result,RES_ERR_LOGIN);
		return {true, result};
	}else{
		vec content;
		std::function<void ()> then = [](){return;};
		std::function<void(string, vec)> f1 = [&content](string key, vec value){
			vec_append(content,key);
			vec_append(content,"\n");
			return;
		};
		fields->kv_store.do_all_readonly(f1,then);
		vec res;
		this->fields->quota_table.do_with(user_name, [&](Quotas* entry){
			if(!entry->requests.check(1)) {
				res = vec_from_string(RES_ERR_QUOTA_REQ);
			} else if (!entry->downloads.check(content.size())) {
				entry->requests.add(1);
				res = vec_from_string(RES_ERR_QUOTA_DOWN);
			} else {
				entry->requests.add(1);
				entry->downloads.add(content.size());
			}
		});
		if(res.size()){
			return {true,res};
		}
		
		return {false, content};
	}
  return {true, vec_from_string(RES_ERR_NO_DATA)};
};

/// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
/// string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_top(const string &user_name, const string &pass) {
  string rv = this->fields->mru.get();
  vec res;
  this->fields->quota_table.do_with(user_name, [&](Quotas* entry){
    if(!entry->requests.check(1)) {
      res = vec_from_string(RES_ERR_QUOTA_REQ);
    } else if(!entry->downloads.check(rv.size())) {
      entry->requests.add(1);
      res = vec_from_string(RES_ERR_QUOTA_DOWN);
    } else {
      entry->requests.add(1);
      entry->downloads.add(rv.size());
    }
  });
  if(res.size()) return {true, res};
  if(!rv.length()) {
    return {true, vec_from_string(RES_ERR_NO_DATA)};
  }
  return {false, vec_from_string(rv)};
};

/// Close any open files related to incremental persistence
///
/// NB: this cannot be called until all threads have stopped accessing the
///     Storage object
void Storage::shutdown() {}

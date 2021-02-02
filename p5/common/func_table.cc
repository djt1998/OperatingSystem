#include <atomic>
#include <dlfcn.h>
#include <iostream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/file.h"
#include "../common/functypes.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "func_table.h"

using namespace std;

/// func_table::Internal is the private struct that holds all of the fields of
/// the func_table object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
///
/// Among other things, this struct will probably need to have a map of loaded
/// functions and a shared_mutex.  The map will probably need to hold some kind
/// of struct that is able to support graceful shutdown, as well as the
/// association of names to map/reduce functions
struct func_table::Internal {
  map<string,pair<map_func, reduce_func>> functions;
  mutable shared_mutex mutex;
  vector<void*> open_handles;
  vector<string> file_names;
  atomic<int> counter;
};

/// Construct a function table for storing registered functions
func_table::func_table() : fields(new Internal()) {}

/// Destruct a function table
func_table::~func_table() = default;

/// Register the map() and reduce() functions from the provided .so, and
/// associate them with the provided name.
///
/// @param mrname The name to associate with the functions
/// @param so     The so contents from which to find the functions
///
/// @returns a vec with a status message

// extern "C" {
//   string randomString(int n) 
// { 
//     char alphabet[26] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 
//                           'h', 'i', 'j', 'k', 'l', 'm', 'n',  
//                           'o', 'p', 'q', 'r', 's', 't', 'u', 
//                           'v', 'w', 'x', 'y', 'z' }; 
  
//     string res = ""; 
//     for (int i = 0; i < n; i++)  
//         res = res + alphabet[rand() % 26]; 
      
//     return res; 
// } 
//}
vec func_table::register_mr(const string &mrname, const vec &so) {
  shared_lock lock(fields->mutex);
  //Check if the functions are already in the database 
  auto it=fields->functions.find(mrname);
  if(it != fields->functions.end()){
    return vec_from_string(RES_ERR_FUNC);
  }
  //Create the temp file
  string tmp = "tmp"+to_string(fields->counter);
  auto filename ="./obj64" + tmp;// + ".so";
  vec content = so;
  write_file(filename, reinterpret_cast<char*>(content.data()), content.size());
  
    // Get handle from the file created
  void* handle = dlopen(filename.c_str(), RTLD_LAZY);
  if (!handle) {
      remove(filename.c_str());
      return vec_from_string(RES_ERR_SO);
  }
  string func_name1 = "map";
  string func_name2 = "reduce";
  char* error;
  //Use handle to get the function 
  map_func map_f = (map_func)dlsym(handle, func_name1.c_str());
  
  reduce_func red_f = (reduce_func)dlsym(handle, func_name2.c_str());
  if ((error = dlerror()) != NULL) {
    dlclose(handle);
    remove(filename.c_str());
    return vec_from_string(RES_ERR_SO);
  }

 
  pair<map_func, reduce_func> f = make_pair(map_f,red_f);
  fields->functions.insert(make_pair(mrname,f));
  
  fields->open_handles.push_back(handle);
  fields->file_names.push_back(filename);
  fields->counter++;
  shared_lock unlock(fields->mutex);
  return vec_from_string(RES_OK);
  
  
}

/// Get the (already-registered) map() and reduce() functions asssociated with
/// a name.
///
/// @param name The name with which the functions were mapped
///
/// @returns A pair of function pointers, or {nullptr, nullptr} on error
pair<map_func, reduce_func> func_table::get_mr(const string &mrname) {
  auto it=fields->functions.find(mrname);
  if(it != fields->functions.end()){
    return (*it).second;
  }
  else{
    return {nullptr, nullptr};
  }
  
}

/// When the function table shuts down, we need to de-register all the .so
/// files that were loaded.
void func_table::shutdown() {
  shared_lock lock(fields->mutex);
  for(auto it = fields->open_handles.begin(); it != fields->open_handles.end(); it++){
    dlclose(*it);
  }
  
  for(auto i = fields->file_names.begin(); i != fields->file_names.end(); i++){
    remove((*i).c_str());
  }
  fields->functions.clear();
  shared_lock unlock(fields->mutex);
}
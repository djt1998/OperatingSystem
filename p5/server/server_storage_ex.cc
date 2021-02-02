#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

#include "../common/contextmanager.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_storage.h"
#include "server_storage_internal.h"

using namespace std;


/// Perform the child half of a map/reduce communication
///
/// @param in_fd   The fd from which to read data from the parent
/// @param out_fd  The fd on which to write data to the parent
/// @param mapper  The map function to run on each pair received from the
///                parent
/// @param reducer The reduce function to run on the results of mapper
///
/// @returns false if any error occurred, true otherwise
bool child_mr(int in_fd, int out_fd, map_func mapper, reduce_func reducer)
{
  char re;
  vec re_result;
  while (read(in_fd, &re, 1)){
    re_result.push_back(re);
  }
  close(in_fd);
  vector<pair<string, vec>> kv_pair;
  auto it = re_result.begin();
  while (it != re_result.end())
  {
	//convert vec to string
	string length_str(it, it + 4);
    unsigned char* buf = (unsigned char *)length_str.data();
    int length = unsigned((buf[0]) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)); //or binary to int
    it += 4;
    string result(it, it + length);
    it += length;
    string key = result;
	
	//convert vec to string
	string length_str1(it, it + 4);
    unsigned char* buf1 = (unsigned char *)length_str1.data();
    length = unsigned((buf1[0]) | (buf1[1] << 8) | (buf1[2] << 16) | (buf1[3] << 24)); //or binary to int
    it += 4;
    string result1(it, it + length);
    it += length;
    string value = result1;
	
    kv_pair.push_back({key, vec_from_string(value)});
  }

  /* apply functions to kv pairs */
  vector<vec> results;
  for (auto i : kv_pair)
    results.push_back(mapper(i.first, i.second));
  vec reduce_result = reducer(results);
  /* write back applied result to parent */
  if (write(out_fd, (const char *)(reduce_result.data()), reduce_result.size()) == -1)
    return false;
  close(out_fd);
  return true;
}

/// Register a .so with the function table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param mrname    The name to use for the registration
/// @param so        The .so file contents to register
///
/// @returns A vec with the result message
vec Storage::register_mr(const string &user_name, const string &pass,
                         const string &mrname, const vec &so)
{
  if (!auth(user_name, pass))
    return vec_from_string(RES_ERR_LOGIN);
  if (user_name != fields->admin_name)
    return vec_from_string(RES_ERR_LOGIN);

  if (fields->funcs.get_mr(mrname).first != nullptr)
    return vec_from_string(RES_ERR_FUNC);

  return fields->funcs.register_mr(mrname, so);
};

/// Run a map/reduce on all the key/value pairs of the kv_store
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, to authenticate
/// @param mrname    The name of the map/reduce functions to use
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
pair<bool, vec> Storage::invoke_mr(const string &user_name, const string &pass,
                                   const string &mrname)
{
  if (!auth(user_name, pass)){
    return make_pair(true, vec_from_string(RES_ERR_LOGIN));
  }
  pair<map_func, reduce_func> func_pairs = fields->funcs.get_mr(mrname);

  //create pipes for passing content
  int pw[2];
  int cw[2];
  //check if we set up pipe correctly
  if (pipe(pw) == -1){
    return make_pair(true, vec_from_string(RES_ERR_SERVER));
  }
  if (pipe(cw) == -1){
    return make_pair(true, vec_from_string(RES_ERR_SERVER));
  }
  //set up pid and w
  pid_t pid; 
  pid_t wip;
  int status;
  //check if fork has error
  if ((pid = fork()) < 0) {
    return make_pair(true, vec_from_string(RES_ERR_SERVER));
  }
  else if (pid > 0) //parent
  {
    //close read and write for client write pipe and parent write pipe
    close(cw[1]);
    close(pw[0]);

    //iterate key and value pairs
    vec data;
    fields->kv_store.do_all_readonly([&](string key, const vec &value) { 
      vec_append(data, key.size());
      vec_append(data, key);
      vec_append(data, value.size());
      vec_append(data, value); }, [&]() {});
    
    if (write(pw[1], (const char *)(data.data()), data.size()) == -1){
      return make_pair(true, vec_from_string(RES_ERR_SERVER));
	}
    close(pw[1]); 

    // wait for child to complete task 
    if ((wip = waitpid(pid, &status, WUNTRACED | WCONTINUED)) == -1){
      return make_pair(true, vec_from_string(RES_ERR_SERVER));
	}
    if (WIFEXITED(status))
    {
      int exit_status = WEXITSTATUS(status);
      if (exit_status != 0) return make_pair(true, vec_from_string(RES_ERR_SERVER)); // if task failed, return error
    }
    // read from child's output and return
    char read_in;
    vec result_from_child;
    while (read(cw[0], &read_in, 1)){
      result_from_child.push_back(read_in);
	}
    close(cw[0]);
    return make_pair(false, result_from_child);
  }
  else //child fork
  {
    //close pipe for parent write and children write
    close(pw[1]);
    close(cw[0]);
    //use child_mr here
    if (child_mr(pw[0], cw[1], func_pairs.first, func_pairs.second)){
      exit(EXIT_SUCCESS);
	}
    else{
      exit(EXIT_FAILURE);
	}
  }
}
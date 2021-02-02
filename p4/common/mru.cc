#include <deque>
#include <mutex>
#include <string> 
#include "mru.h"
#include <thread>
#include <atomic>
#include <utility>
#include <iostream>
#include<bits/stdc++.h> 
#include <iterator>
#include <shared_mutex>
using namespace std;

/// mru_manager::Internal is the class that stores all the members of a
/// mru_manager object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct mru_manager::Internal {
  // NB: You probably want to add a few more fields and methods here
  deque<string> tracks;
  size_t num;
  mutex lock;
  //mutable std::shared_mutex mtx;
  /// Construct the Internal object by setting the fields that are
  /// user-specified
  ///
  /// @param elements The number of elements that can be tracked
  Internal(size_t elements): num(elements){
    // num = elements;
  }
};

/// Construct the mru_manager by specifying how many things it should track
mru_manager::mru_manager(size_t elements) : fields(new Internal(elements)) {
}

/// Destruct an mru_manager
mru_manager::~mru_manager() = default;

/// Insert an element into the mru_manager, making sure that (a) there are no
/// duplicates, and (b) the manager holds no more than /max_size/ elements.
///
/// @param elt The element to insert
void mru_manager::insert(const string &elt) {
  //Check if the element is in the deque
  //lock_guard<mutex> lock(fields->lock);
  remove(elt);
  lock_guard<mutex> lock(fields->lock);
  //fields->mtx.lock();
  // auto it = std::find(fields->tracks.begin(),fields->tracks.end(),elt);
  
  // if(it != fields->tracks.end()){
  //   //Check if the size of the decque is bigger than the max size
  //   if(fields->tracks.size() < fields->num){
  //     //Push the new element into the front of the deque
  //     fields->tracks.push_front(elt);
  //   }
  // }
  // else{
  //   //If the element is already in the deque, remove it and move it to the fron of the deque
  //   fields->tracks.erase(it);
  //   fields->tracks.push_front(elt);
  // }  
  if(fields->tracks.size() < fields->num){
  //Push the new element into the front of the deque
    fields->tracks.push_front(elt);
}
  else{
    fields->tracks.pop_back();
    fields->tracks.push_front(elt);
  }
//fields->mtx.unlock();
}

/// Remove an instance of an element from the mru_manager.  This can leave the
/// manager in a state where it has fewer than max_size elements in it.
///
/// @param elt The element to remove
void mru_manager::remove(const string &elt) {
  //Remove the element from the deque 
  lock_guard<mutex> lock(fields->lock);
  //fields->mtx.lock();
  
  for(auto it=fields->tracks.begin(); it != fields->tracks.end(); it++){
    if(!it->compare(elt)){
      fields->tracks.erase(it);
      break;
    }
  }
  //fields->mtx.unlock();
}

/// Clear the mru_manager
void mru_manager::clear() {
  //Clean the deque 
  lock_guard<mutex> lock(fields->lock);
  // fields->mtx.lock();
  fields->tracks.clear();
  //fields->mtx.unlock();
}

/// Produce a concatenation of the top entries, in order of popularity
///
/// @returns A newline-separated list of values
string mru_manager::get() { 
  //Create a new string
  lock_guard<mutex> lock(fields->lock);
  // fields->mtx.lock_shared();
  string output;
  
  for(auto it=fields->tracks.begin(); it != fields->tracks.end(); it++){
    if(it ==fields-> tracks.begin()){
      output += *it;
    }
    else{
      output += "\n";//Add the newline symbol to sepaerated the list
      output += *it; //Add element into string
    }
    
      
  }
  // fields->mtx.unlock();
  return output; 
  };
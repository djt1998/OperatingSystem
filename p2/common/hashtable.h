#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>
using namespace std;

/// ConcurrentHashTable is a concurrent hash table (a Key/Value store).  It is
/// not resizable, which means that the O(1) guarantees of a hash table are lost
/// if the number of elements in the table gets too big.
///
/// The ConcurrentHashTable is templated on the Key and Value types
///
/// The general structure of the ConcurrentHashTable is that we have an array of
/// buckets.  Each bucket has a mutex and a vector of entries.  Each entry is a
/// pair, consisting of a key and a value.  We can use std::hash() to choose a
/// bucket from a key.
template <typename K, typename V> class ConcurrentHashTable {


public:

  //Create the a struct which can be declare as a vector type
  struct my_buckets{
    mutex lock;
    vector<pair <K,V>> entry; 
  };

  vector<my_buckets> table;

  size_t bucket;
  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets):table(_buckets){
    bucket = _buckets;
  }; 
  // {
  //   for(size_t i = 0; i < _buckets;++i){
  //     //my_buckets obj;
  //     table.push_back(my_buckets());
      
  //   }
  // }

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {

    for(int i = 0; i < int(table.size());++i){
      table[i].lock.lock();
      table[i].entry.clear();
    }

    for(int i = 0; i < int(table.size());++i){
      table[i].lock.unlock();
    }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key The key to insert
  /// @param val The value to insert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  /// existed in the table
  bool insert(K key, V val) { 
    hash<K> hash_f;
    size_t hash_key = hash_f(key);
    int index = (static_cast<int>(hash_key)) % bucket;
    lock_guard<mutex> lock(this->table[index].lock);
  
    for(auto i = (table[index].entry).begin(); i != (table[index].entry).end();++i){
      if((*i).first == key){
        return false;
      }
    }
    
    table[index].entry.push_back(make_pair(key,val));
    return true;

    }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key The key to upsert
  /// @param val The value to upsert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val) { 
    hash<K> hash_f;
    size_t hash_key = hash_f(key);
    int index = (static_cast<int>(hash_key)) % bucket;
    lock_guard<mutex> lock(this->table[index].lock);
  
    for(auto i = (table[index].entry).begin(); i != (table[index].entry).end();++i){
      if((*i).first == key){
        (*i).second = val;
        return false;
      }
    }
    
    table[index].entry.push_back(make_pair(key,val));
    return true;
    }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with(K key, std::function<void(V &)> f) { 
    hash<K> hash_f;
    size_t hash_key = hash_f(key);
    int index = (static_cast<int>(hash_key)) % bucket;
    lock_guard<mutex> lock(this->table[index].lock);

    //auto v = [&]{};
    for(auto i = (table[index].entry).begin(); i != (table[index].entry).end();++i){
      if((*i).first == key){
        f((*i).second);
        return true;
      }
    }
    

    return false; 
    }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with_readonly(K key, std::function<void(const V &)> f) {

    hash<K> hash_f;
    size_t hash_key = hash_f(key);
    int index = (static_cast<int>(hash_key)) % bucket;
    lock_guard<mutex> lock(this->table[index].lock);

    for(auto i = (table[index].entry).begin(); i != (table[index].entry).end();++i){
      if((*i).first == key){
        f((*i).second);
        return true;
      }
    }
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key The key whose mapping should be removed
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key) { 
    hash<K> hash_f;
    size_t hash_key = hash_f(key);
    int index = (static_cast<int>(hash_key)) % bucket;
    lock_guard<mutex> lock(this->table[index].lock);
  
    for(auto i = (table[index].entry).begin(); i != (table[index].entry).end();++i){
      if((*i).first == key){
        (table[index].entry).erase(i);
        return true;
      }
    }

    return false; 
    }

  /// Apply a function to every key/value pair in the ConcurrentHashTable.  Note
  /// that the function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  void do_all_readonly(std::function<void(const K, const V &)> f,
                       std::function<void()> then) {
    auto len = bucket;
    for(int i = 0; i < int(table.size());++i){
      table[i].lock.lock();
    }

    for(auto i = 0; i < (int)len; i++){
      for(auto m = (table[i].entry).begin(); m != (table[i].entry).end();++m){
        f((*m).first,(*m).second);
      }
    }

    then();
    for(int i = 0; i < int(table.size());++i){
      table[i].lock.unlock();
    }
                       }
};

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <unistd.h>
#include <vector>


#include "pool.h"

using namespace std;

/// thread_pool::Internal is the class that stores all the members of a
/// thread_pool object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct thread_pool::Internal {

  function<bool(int)> execute_task; 
  function<void()> end_func;
  /// construct the Internal object by setting the fields that are
  /// user-specified
  ///
  /// @param handler The code to run whenever something arrives in the pool
  Internal(function<bool(int)> handler) {
    this->execute_task = handler;
  }

  queue<int> task;//Normal queue

  vector<thread> pool;//A vector to save the threads
  
  condition_variable queue_cv; //A condition variable for queue, we want to make queue sleep when there is no work

  atomic<bool> shut = false;
  mutex lock_check;

  function<void()> thread_fun = [&](){

    while(true){
      unique_lock<std::mutex> lk(lock_check);
      // while();
      queue_cv.wait(lk);

      if(shut){
        lk.unlock();
        break;
      }
      else{
        if(!(task.empty())){
          int sd = task.front();
          task.pop();
          lk.unlock();
          bool result = execute_task(sd);
          if(result){
            shut = true;
            end_func();
          }
          close(sd);
          // else{

          // }
        }
      }
    }
  };

  //function<void()> thread_fun = 
};

/// construct a thread pool by providing a size and the function to run on
/// each element that arrives in the queue
///
/// @param size    The number of threads in the pool
/// @param handler The code to run whenever something arrives in the pool
thread_pool::thread_pool(int size, function<bool(int)> handler)
    : fields(new Internal(handler)) {
      for(int i =0; i<size; i++){
        fields->pool.push_back(thread([&]() {fields->thread_fun();}));
      }
    }

/// destruct a thread pool
thread_pool::~thread_pool() = default;

/// Allow a user of the pool to provide some code to run when the pool decides
/// it needs to shut down.
///
/// @param func The code that should be run when the pool shuts down
void thread_pool::set_shutdown_handler(function<void()> func) {
  this->fields->end_func = func;
}

/// Allow a user of the pool to see if the pool has been shut down
bool thread_pool::check_active() { 
  return !(fields->shut);
}

/// Shutting down the pool can take some time.  await_shutdown() lets a user
/// of the pool wait until the threads are all done servicing clients.
void thread_pool::await_shutdown() {

  lock_guard(fields->lock_check);

  fields->queue_cv.notify_all();

  for(auto &th: fields->pool){
    th.join();
  }
  
  //fields->lock_check.unlock();
}

/// When a new connection arrives at the server, it calls this to pass the
/// connection to the pool for processing.
///
/// @param sd The socket descriptor for the new connection
void thread_pool::service_connection(int sd) {
  fields->task.push(sd);
  fields->queue_cv.notify_one();
}

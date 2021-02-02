// NB: http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <time.h>

#include "quota_tracker.h"

using namespace std;

/// quota_tracker::Internal is the class that stores all the members of a
/// quota_tracker object. To avoid pulling too much into the .h file, we are
/// using the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct quota_tracker::Internal {
  /// An event is a timestamped amount.  We don't care what the amount
  /// represents, because the code below will only sum the amounts in a
  /// collection of events and compare it against a quota.
  struct event {
    /// The time at which the request was made
    time_t when;

    /// The amount of resource consumed at the above time
    size_t amnt;
  };

  // NB: You probably want to add a few more fields here
  deque<event> tracks;
  size_t q_amount;
  size_t max;
  double dur;
  /// Construct the Internal object
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time during the service maximum can be spread out
  Internal(size_t amount, double duration) {
    max = amount;
    dur = duration;
  }
};

/// Construct an object that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time during the service maximum can be spread out
quota_tracker::quota_tracker(size_t amount, double duration)
    : fields(new Internal(amount, duration)) {}

/// Construct a quota_tracker from another quota_tracker
///
/// @param other The quota tracker to use to build a new quota tracker
quota_tracker::quota_tracker(const quota_tracker &other) : fields(new Internal(other.fields->max, other.fields->dur)) {
  // TODO: You'll want to figure out how to make a copy constructor for this
  fields -> tracks = other.fields->tracks;
}

/// Destruct a quota tracker
quota_tracker::~quota_tracker() = default;

/// Decides if a new event is permitted.  The attempt is allowed if it could
/// be added to events, while ensuring that the sum of amounts for all events
/// with (time > now-q_dur), is less than q_amnt.
///
/// @param amount The amount of the new request
///
/// @returns True if the amount could be added without violating the quota
bool quota_tracker::check(size_t amount) { 

  //Check if the time difference is smaller than dur
  // if (difftime(current, fields->tracks.front().when) > fields->dur) {
  //   fields->tracks.erase(fields->tracks.begin());
  // }
  fields->q_amount = 0;
  for (size_t i = 0; i < fields->tracks.size(); i++) {
    if (difftime(time(NULL), fields->tracks[i].when) > fields->dur) {
      fields->tracks.pop_front();
      i--;
    }
    else{
      fields->q_amount += fields->tracks[i].amnt;
    }
  }
  //Check if the total time exceed the max
  if((fields->q_amount+amount) > fields->max){
    return false;
  }

  return true; 
  }

/// Actually add a new event to the quota tracker
void quota_tracker::add(size_t amount) {
  //bool check1 = check(amount);

  quota_tracker::Internal::event instance = {time(NULL),amount};
  fields->tracks.push_back(instance);
}
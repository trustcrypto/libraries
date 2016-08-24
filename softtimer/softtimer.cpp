/**
 * File: SoftTimer.cpp
 * Description:
 * SoftTimer library is a lightweight but effective event based timeshare solution for Arduino.
 *
 * Author: Balazs Kelemen
 * Contact: prampec+arduino@gmail.com
 * https://github.com/prampec/arduino-softtimer
 * Copyright (c) 2016 , Balázs Kelemen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "Arduino.h"
#include "softtimer.h"

/**
 * The main loop is implemented here. You do not ever need to call implement this function
 * if you think in event driven programing.
 */
void loop() {
  SoftTimer.run();
}


/**
 * Register a task in the timer manager.
 */
void SoftTimerClass::add(Task* task) {

  // -- A task should be registered only once.
  this->remove(task);
  
  if(this->_tasks == NULL) {
  
    // -- This is the first task being registered.
    this->_tasks = task;
    
  } else {
  
    Task* lastTask = this->_tasks;
    // -- Find the last task, to build a chain.
    while(lastTask->nextTask != NULL) {
      lastTask = lastTask->nextTask;
    }
    // -- Last task found, let's add this task to the end of the chain.
    lastTask->nextTask = task;
    
  }
  
  task->lastCallTimeMicros = micros() - task->periodMicros; // -- Start immediately after registering.
  task->nextTask = NULL;
}


/**
 * Remove registration of a task in the timer manager.
 */
void SoftTimerClass::remove(Task* task) {
  if(this->_tasks != NULL) {
    if(this->_tasks == task) {
      // -- This was the first task.
      this->_tasks = task->nextTask;
    } else {
      Task* lastTask = this->_tasks;
      // -- Find this task in the chain.
      while(lastTask->nextTask != NULL) {
        if(lastTask->nextTask == task) {
          // -- Remove the task with joining the chain.
          lastTask->nextTask = task->nextTask;
          break;
        }
        lastTask = lastTask->nextTask;
      }
    }
  }
}

/**
 * Walk through the chain looking for task to call.
 */
void SoftTimerClass::run() {
  Task* task = this->_tasks;
  // -- (If this->_tasks is NULL, than nothing is registered.)
  while(task != NULL) {
    this->testAndCall(task);
    task = task->nextTask;
  }
}

/**
 * Test a task and call the callback if its period was passed since last call.
 */
void SoftTimerClass::testAndCall(Task* task) {
  unsigned long now = micros();
  unsigned long calc = task->lastCallTimeMicros + task->periodMicros;
  if(
    ((now >= calc) && (
      (calc >= task->lastCallTimeMicros) // -- Nothing was overflown.
      || (task->lastCallTimeMicros > now) // -- Both timer and interval-end overflows
      ))
    || ((now < task->lastCallTimeMicros) && (task->lastCallTimeMicros <= calc))) // -- timer overflows, but interval-end does not
  {
    task->callback(task);
    task->lastCallTimeMicros = now;
  }
}


/**
 * Create a singleton from this manager class.
 */
SoftTimerClass SoftTimer;

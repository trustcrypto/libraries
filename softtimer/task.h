/**
 * File: Task.h
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

#ifndef TASK_H
#define TASK_H

/**
 * Task is a job that should be called repeatedly,
 */
class Task
{
  public:
    /**
     * Construct a task with defining a period and a callback handler function.
     *  periodMs - Call the task in every X milliseconds. Do not add values greater then 4,294,967, which is about 71 minutes!
     *  callback - Is a static function reference, the function will be called each time. The callback function need to
     * have one argument, which is the currently running task.
     */
    Task(unsigned long periodMs, void (*callback)(Task* me));
    
    /**
     * The timeslot in milliseconds the handler should be called.
     * Do not add values greater then 4,294,967, which is about 71 minutes!
     */
    void setPeriodMs(unsigned long periodMs);

    /**
     * The timeslot in milliseconds the handler should be called. If the value is near 1 the handler will be called in every loop.
     */
    unsigned long periodMicros;
    
    /**
     * The last call (start) time of the task. You can reset the task by setting this value to micros().
     */
    volatile unsigned long lastCallTimeMicros;
    
    /**
     * The function that will be called when the period time was passed since the lastCallTime. This member is for internal use only.
     */
    void (*callback)(Task* me);
    /**
     * This member is for internal use only. Do not change!
     */
    Task* nextTask;
  private:
};

#endif

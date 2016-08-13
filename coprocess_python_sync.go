package main

/*
extern void MutexLock();
*/
import "C"

import(
  "sync"
)

var GILMutex sync.Mutex

//export MutexLock
func MutexLock() {
  GILMutex.Lock()
}

//export MutexUnlock
func MutexUnlock() {
  GILMutex.Unlock()
}

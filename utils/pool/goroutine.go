package pool

import (
	"edu.buaa.soft/CVEGetter/config"
	"sync"
)

type GoRoutineLock struct {
	IndexNow int
	PoolSize int
	Locks    []*sync.Mutex
	PoolLock *sync.Mutex
}

var (
	goRoutineLock *GoRoutineLock
)

func InitGoRoutineLock() {
	size := config.LoadConfig().GoRoutineLockPoolSize
	locks := []*sync.Mutex{}
	for i := 0; i < size; i++ {
		locks = append(locks, &sync.Mutex{})
	}
	goRoutineLock = &GoRoutineLock{
		IndexNow: 0,
		PoolSize: 10,
		Locks:    locks,
		PoolLock: &sync.Mutex{},
	}
}

func GetGoRoutineLock() *sync.Mutex {
	goRoutineLock.PoolLock.Lock()
	defer goRoutineLock.PoolLock.Unlock()
	lock := goRoutineLock.Locks[tokenPool.IndexNow]
	tokenPool.IndexNow++
	if tokenPool.IndexNow >= tokenPool.PoolSize {
		tokenPool.IndexNow = 0
	}
	return lock
}

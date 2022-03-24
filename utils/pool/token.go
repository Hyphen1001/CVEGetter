package pool

import (
	"sync"

	"edu.buaa.soft/CVEGetter/config"
)

type TokenPool struct {
	IndexNow int
	PoolSize int
	Tokens   []string
	PoolLock *sync.Mutex
}

var tokenPool *TokenPool

func InitTokenPool() {
	tokenPool = &TokenPool{
		IndexNow: 0,
		PoolSize: len(config.LoadConfig().GithubTokens),
		Tokens:   config.LoadConfig().GithubTokens,
		PoolLock: &sync.Mutex{},
	}
}

func GetToken() string {
	tokenPool.PoolLock.Lock()
	defer tokenPool.PoolLock.Unlock()
	token := tokenPool.Tokens[tokenPool.IndexNow]
	tokenPool.IndexNow++
	if tokenPool.IndexNow >= tokenPool.PoolSize {
		tokenPool.IndexNow = 0
	}
	return token
}

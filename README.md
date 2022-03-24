#README
在开始项目之前，应该做的工作:
####0、环境要求：go-1.16
####1、配置./conf/conf.yaml  
各个配置的含义如下（带*为必须配置项）： 
* *GithubPassword：密码
* *GithubUsername：用户名
* *GithubTokens: token池，包含的token取决于GitAPIRateLimit，亦即QPS，如果与QPS不匹配（过少），运行时有可能会应为git open-api访问受限而被影响
* LogLevel：日志等级  
* GoRoutineLockPoolSize：线程池最大线程数  
* GitAPIRateLimit: 1000/(最理想情况下的QPS)，即每次请求的sleep的时长，单位为ms
* AimLanguages：目标语言  
####2、在terminal将当前路径切换到start.sh所在路径，执行./start.sh

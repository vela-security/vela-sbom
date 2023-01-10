# sbom
> vela sbom 供应链软件分析 支持 windows 和 linux  <br />
> vela manager 会 自动扫描和查询相关数据接口,分析组件漏洞

## 内置方法
- [vela.sbom.file(path , bool)](#扫描文件)&emsp;扫描文件
- [vela.sbom.client(cfg)](#客户端)&emsp;客户端对象

## 扫描文件
> [sbom](#软件物料清单) = vela.sbom.file(path , bool) <br />
> path:扫描文件名称    bool:是否上报供应链sbom信息   sbom: [软件物料清单](#软件物料清单)

```lua
    local sbom = vela.sbom.file("snapshot.jar" , true)
    print(sbom.cdx)
    print(sbom.sdx)
    print(sbom.catalog)

```

## 客户端
> client = vela.sbom.client{name,remote,report,cache,timeout,bucket} <br />
> name:名称 &emsp; remote:是否查寻远程信息 &emsp; report:是否上报  &emsp; cache:是否缓存 &emsp; timeout:扫描超时时间  &emsp; bucket: 存储路径

内置方法:
**sync_ 的方法是采用启用新的线程不会阻塞当前业务的模式扫描,push_ 的方法采用的的是推迟扫描的模式 防止服务占用业务高峰期cpu和内存**
- [client.pipe(v)](#) &emsp;遍历catalog信息
- [client.filter(cnd)](#)&emsp;筛选过滤扫描文件
- [client.filter_by_catalog(cnd)](#)&emsp;通过[catalog](#物料信息)过滤
- [limit(int ,time)](#)&emsp;扫描限速 标准的限速器
- [by_file(v...)](#)&emsp;扫描文件
- [by_pid(v...)](#)&emsp;通过PID扫描
- [by_pid_track(v...)](#)&emsp;扫描PID相关的所有句柄信息
- [by_process(v...)](#)&emsp;扫描进程对象文件
- [by_process_track(cnd,v...)](#)&emsp;扫描进程句柄文件
- [by_track(v...)](#)&emsp;通过全局句柄信息扫描
- [sync_by_file(v...)](#)&emsp;异步扫描文件
- [sync_by_pid(v...)](#)&emsp;异步通过PID扫描
- [sync_by_pid_track(cnd,v...)](#)&emsp;异步扫描PID相关的所有句柄信息
- [sync_by_process(v...)](#)&emsp;异步扫描进程对象文件
- [sync_by_process_track(cnd,v...)](#)&emsp;异步扫描进程句柄文件
- [sync_by_track(cnd,v...)](#)&emsp; 异步通过全局句柄信息扫描
- [push_by_file(v...)](#)&emsp; 延时扫描文件
- [push_by_pid(v...)](#)&emsp; 延时通过PID扫描
- [push_by_pid_track(cnd,v...)](#)&emsp;延时扫描PID相关的所有句柄信息
- [push_by_process(v...)](#)&emsp;延时扫描进程对象文件
- [push_by_process_track(cnd,v...)](#)&emsp;延时扫描进程句柄文件
- [push_by_track(cnd,v...)](#)&emsp;延时通过全局句柄信息扫描
- [task(bool)](#)&emsp;启动延时任务,参数:是否清除
- [clear()](#)&emsp;清除本地缓存信息

```lua
    local cli = vela.sbom.client{
        name = "client",
        timeout = 1000, -- 读取文件超时 millisecond
        report = true,  -- 上报结果
        cache = false,  -- 是否缓存
        remote = true,  -- 是否查询远程
    }
    cli.limit(1 , 10000) -- millisecond
    
    cli.filter("size > 100" ,
            "ext !eq json,txt" ,
            "mtime > 1000000" , 
            "name !re *windows*")
    cli.start()


    cli.pipe(function(catalog)
        print(catalog)
    end)
    cli.start()

    cli.by_pid(1)
    cli.by_pid_track("type = file" , 122 , 333)
    cli.by_process(p) --process object
    cli.by_process_track("type = file" , p1 , p2)     -- p1,p2 process object
    cli.sync_by_track("type = file" , "java" , "aaa") -- 异步扫描句柄信息

```

## 软件物料清单
> sbom 软件物料清单 存储分析 文件的软件的物料清单


内置方法:
- sdx &emsp;spdx  信息 json
- cdx &emsp;cyclondx 信息 json
- [catalog](#物料信息)&emsp;物料信息
- [reset](#清空数据)&emsp;清空数据重置内存

```lua
    local sbom = vela.sbom.file("aaa.jar" , true)
    print(sbom.cdx)
    print(sbom.sdx)
    print(sbom.catalog)
    sbom.catalog.pipe(function(package)
        --package 
    end)
    sbom.reset()

``` 

## 物料信息
> catalog 物料信息 相关数据信息

内置字段:
- filename
- checksum
- algorithm
- mtime
- size
- pkg_size
- [delete(string , version)](#)&emsp; 删除包信息
- [pipe(package)](#)&emsp;遍历包内容[package](#package)
- [reset()](#)

```lua
    local cli = vela.sbom.client{}
    cli.pipe(function(catalog) 
        print(catalog.filename)
        print(catalog.checksum)
        print(catalog.algorithm)
        print(catalog.mtime)
        print(catalog.size)
        -- 遍历 
        catalog.pipe(function(package)
            print(package.purl)
            print(package.version)
            print(package.name)
            print(package.algorithm)
            print(package.checksum)
            print(package.licenses)
            print(package.language)
        end)
    end)

```

## package
> 封装单个组件信息 catalog 中遍历的包信息

内置字段:
- purl &emsp;package&nbsp;url&nbsp;唯一标识
- version
- name
- algorithm
- checksum
- licenses
- language


```lua
    print(p.purl) 
    print(p.name)
    
```

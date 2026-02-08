# FUSE的内核实现

## 1 简介

FUSE（Filesystem in Userspace）允许在用户空间创建文件系统，而不需要修改内核代码。用户程序通过FUSE库与内核模块进行通信，实现文件系统的功能。

## 2 用户程序

我们使用libfuse提供的示例程序`hello_ll.c`来演示FUSE的使用。核心的代码如下：

```c
// file: libfuse/example/hello_ll.c
...
int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config *config;
	int ret = -1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;
        ...

	se = fuse_session_new(&args, &hello_ll_oper,
			      sizeof(hello_ll_oper), NULL);
	if (se == NULL)
	    goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
	    goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
	    goto err_out3;

	fuse_daemonize(opts.foreground);

	/* Block until ctrl+c or fusermount -u */
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else {
		config = fuse_loop_cfg_create();
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);
		ret = fuse_session_loop_mt(se, config);
		fuse_loop_cfg_destroy(config);
		config = NULL;
	}

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
```

编译并运行`hello_ll.c`程序，如下：

```bash
./hello_ll -d -f -s ./mnt
FUSE library version: 3.19.0-rc0
dev unique: 2, opcode: INIT (26), nodeid: 0, insize: 104, pid: 0
INIT: 7.42
flags=0x73fffffb
max_readahead=0x00020000
   INIT: 7.45
   flags=0x00400000
   max_readahead=0x00020000
   max_write=0x00100000
   max_background=0
   congestion_threshold=0
   time_gran=1
   unique: 2, success, outsize: 80
dev unique: 4, opcode: ACCESS (34), nodeid: 1, insize: 48, pid: 2648
   unique: 4, error: -38 (Function not implemented), outsize: 16
dev unique: 6, opcode: LOOKUP (1), nodeid: 1, insize: 47, pid: 2648
   unique: 6, error: -2 (No such file or directory), outsize: 16
...
```

在另外的终端中，我们可以查看挂载点`./mnt`下的文件列表，如下：

```bash
$ ls ./mnt
hello
$ cat ./mnt/hello 
Hello World!
```

退出`hello_ll`程序后，我们可以在挂载点`./mnt`下查看文件列表，此时已无文件。如下：

```bash
$ ls ./mnt
```

## 3 实现原理

### 3.1 创建FUSE会话

在`main()`函数中，我们调用`fuse_session_new()`创建一个FUSE会话（session）。该函数实现如下：

```c
// file: libfuse/lib/compat.c
struct fuse_session *fuse_session_new(struct fuse_args *args,
				      const struct fuse_lowlevel_ops *op,
				      size_t op_size, void *userdata)
{
	return fuse_session_new_30(args, op, op_size, userdata);
}
```

其中`op`参数是一个指向`struct fuse_lowlevel_ops`结构体的指针，该结构体定义了FUSE文件系统的操作函数。`hello_ll`示例程序中为`hello_ll_oper`，如下：

```c
// file: libfuse/example/hello_ll.c
static const struct fuse_lowlevel_ops hello_ll_oper = {
	.init = hello_ll_init,
	.lookup = hello_ll_lookup,
	.getattr = hello_ll_getattr,
	.readdir = hello_ll_readdir,
	.open = hello_ll_open,
	.read = hello_ll_read,
	.setxattr = hello_ll_setxattr,
	.getxattr = hello_ll_getxattr,
	.removexattr = hello_ll_removexattr,
};
```

`fuse_session_new`函数是对`fuse_session_new_30`函数的封装，而后者是对`fuse_session_new_versioned`函数的封装，后者实现具体功能，如下：

```c
// file: libfuse/lib/fuse_lowlevel.c
struct fuse_session *
fuse_session_new_versioned(struct fuse_args *args,
			   const struct fuse_lowlevel_ops *op, size_t op_size,
			   struct libfuse_version *version, void *userdata)
{
	int err;
	struct fuse_session *se;
	struct mount_opts *mo;
        ...
        // 创建fuse_session结构体
 	se = (struct fuse_session *) calloc(1, sizeof(struct fuse_session));
	if (se == NULL) { ... }

	se->fd = -1;
	se->conn.max_write = FUSE_DEFAULT_MAX_PAGES_LIMIT * getpagesize();
	se->bufsize = se->conn.max_write + FUSE_BUFFER_HEADER_SIZE;
	se->conn.max_readahead = UINT_MAX;

        // 检查是否支持uring
	se->uring.enable = getenv("FUSE_URING_ENABLE") ?
				   atoi(getenv("FUSE_URING_ENABLE")) :
				   SESSION_DEF_URING_ENABLE;
	se->uring.q_depth = getenv("FUSE_URING_QUEUE_DEPTH") ?
				    atoi(getenv("FUSE_URING_QUEUE_DEPTH")) :
				    SESSION_DEF_URING_Q_DEPTH;

        // 解析命令行参数
	if(fuse_opt_parse(args, se, fuse_ll_opts, NULL) == -1) { ... }
        // 解析挂载选项
	mo = parse_mount_opts(args);
        ...
        // 初始化请求队列
        list_init_req(&se->list);
	list_init_req(&se->interrupts);
	list_init_nreq(&se->notify_list);
	se->notify_ctr = 1;
        // 初始化互斥锁和信号量
	pthread_mutex_init(&se->lock, NULL);
	sem_init(&se->mt_finish, 0, 0);
	pthread_mutex_init(&se->mt_lock, NULL);
        // 创建线程本地存储键
	err = pthread_key_create(&se->pipe_key, fuse_ll_pipe_destructor);
	if (err) { ... }

        // 复制操作函数
        memcpy(&se->op, op, op_size);
        // 获取当前用户ID
	se->owner = getuid();
	se->userdata = userdata;

	se->mo = mo;
	se->version = *version;

	return se;
        ...
}
```

### 3.2 挂载FUSE文件系统

#### 3.2.1 用户空间挂载FUSE文件系统

在`main()`函数中，我们调用`fuse_session_mount()`挂载FUSE文件系统。该函数实现如下：

```c
// file: libfuse/lib/fuse_lowlevel.c
int fuse_session_mount(struct fuse_session *se, const char *_mountpoint)
{
	int fd;
	char *mountpoint;
        // 复制挂载点路径
	mountpoint = strdup(_mountpoint);
	if (mountpoint == NULL) { ... }

        // 确保0、1、2文件描述符已经打开，防止被FUSE使用
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

        // 解析`/dev/fd/N`获取挂载点路径中的FUSE文件描述符
	fd = fuse_mnt_parse_fuse_fd(mountpoint);
	if (fd != -1) {
		if (fcntl(fd, F_GETFD) == -1) { ... }
		se->fd = fd;
		return 0;
	}

        // 调用`fuse_kern_mount`挂载FUSE文件系统
	fd = fuse_kern_mount(mountpoint, se->mo);
	if (fd == -1) goto error_out;
	se->fd = fd;
        // 保存挂载点路径
	se->mountpoint = mountpoint;

	return 0;
}
```

`fuse_kern_mount`函数解析挂载参数后，通过`fuse_mount_sys`或`fuse_mount_fusermount`方式挂载FUSE文件系统。`fuse_mount_sys`通过`/dev/fuse`设备文件挂载FUSE文件系统，而`fuse_mount_fusermount`则通过`fusermount3`命令挂载FUSE文件系统。我们分析`fuse_mount_sys`函数实现，如下：

```c
// file: libfuse/lib/mount.c
static int fuse_mount_sys(const char *mnt, struct mount_opts *mo,
			  const char *mnt_opts)
{
	char tmp[128];
        // 获取FUSE设备文件路径，默认是`/dev/fuse`
	const char *devname = getenv(FUSE_KERN_DEVICE_ENV) ?: "/dev/fuse";
	char *source = NULL;
	char *type = NULL;
	struct stat stbuf;
	int fd;
	int res;

        // 检查挂载点路径是否存在
	res = stat(mnt, &stbuf);
	if (res == -1) { ... }

        // 打开FUSE设备文件
	fd = open(devname, O_RDWR | O_CLOEXEC);
	if (fd == -1) { ... }
	if (!O_CLOEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);

        // 构建挂载选项字符串
	snprintf(tmp, sizeof(tmp),  "fd=%i,rootmode=%o,user_id=%u,group_id=%u",
		 fd, stbuf.st_mode & S_IFMT, getuid(), getgid());

	res = fuse_opt_add_opt(&mo->kernel_opts, tmp);
	if (res == -1)
		goto out_close;

	source = malloc((mo->fsname ? strlen(mo->fsname) : 0) +
			(mo->subtype ? strlen(mo->subtype) : 0) +
			strlen(devname) + 32);

	type = malloc((mo->subtype ? strlen(mo->subtype) : 0) + 32);
	if (!type || !source) { ... }

        // 设置挂载类型
	strcpy(type, mo->blkdev ? "fuseblk" : "fuse");
	if (mo->subtype) {
		strcat(type, ".");
		strcat(type, mo->subtype);
	}
	strcpy(source,
	       mo->fsname ? mo->fsname : (mo->subtype ? mo->subtype : devname));

        // 挂载FUSE文件系统
	res = mount(source, mnt, type, mo->flags, mo->kernel_opts);
	if (res == -1 && errno == ENODEV && mo->subtype) { ... }
	if (res == -1) { ... }

	free(type);
	free(source);

	return fd;
        ...
}
```

#### 3.2.2 `/dev/fuse`文件的说明

用户空间可以通过打开`/dev/fuse`设备文件，获取FUSE文件描述符，然后调用`mount`系统调用挂载FUSE文件系统。该文件在初始化阶段创建，如下：

```c
// file: fs/fuse/dev.c
static struct miscdevice fuse_miscdevice = {
	.minor = FUSE_MINOR,
	.name  = "fuse",
	.fops = &fuse_dev_operations,
};

int __init fuse_dev_init(void)
{
        ...
        // 注册FUSE设备文件
	err = misc_register(&fuse_miscdevice);
	if (err) goto out_cache_clean;
	return 0;
        ...
}
```

`fuse`是一个杂项设备，设备号是`229`，注册成功后的路径是`/dev/fuse`。其对应的文件操作函数是`fuse_dev_operations`，包括`open`、`read`、`write`、`poll`、`release`、`fasync`、`ioctl`等操作，如下：

```c
// file: fs/fuse/dev.c
const struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.open		= fuse_dev_open,
	.read_iter	= fuse_dev_read,
	.splice_read	= fuse_dev_splice_read,
	.write_iter	= fuse_dev_write,
	.splice_write	= fuse_dev_splice_write,
	.poll		= fuse_dev_poll,
	.release	= fuse_dev_release,
	.fasync		= fuse_dev_fasync,
	.unlocked_ioctl = fuse_dev_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
#ifdef CONFIG_FUSE_IO_URING
	.uring_cmd	= fuse_uring_cmd,
#endif
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= fuse_dev_show_fdinfo,
#endif
};
EXPORT_SYMBOL_GPL(fuse_dev_operations);
```

用户空间在挂载`fuse`文件系统时，其中一种途径是通过`/dev/fuse`设备文件获取FUSE文件描述符，需要调用`open`接口，对应函数为`fuse_dev_open`，实现如下：

```c
// file: fs/fuse/dev.c
static int fuse_dev_open(struct inode *inode, struct file *file)
{
        // `private_data`用于存储FUSE连接结构体`fuse_conn`
	file->private_data = NULL;
	return 0;
}
```

#### 3.2.3 挂载`fuse`文件系统

##### (1) `mount`系统调用

`mount`系统调用比较复杂，这里就不详细描述，我们主要关注新挂载(`do_new_mount`)的实现。核心的调用过程如下：

```c
//file: fs/namespace.c
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
        ...
	ret = do_mount(kernel_dev, dir_name, kernel_type, flags, options);
                // 获取挂载点路径
                --> ret = user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
                // 通过挂载点路径挂载文件系统
                --> return path_mount(dev_name, &path, type_page, flags, data_page);
                        // 创建新的挂载点
                        --> return do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name, data_page);
}
```

`do_new_mount` 函数用于创建新的挂载点，核心的调用过程如下：

```c
// file: fs/namespace.c
static int do_new_mount(const struct path *path, const char *fstype,
			int sb_flags, int mnt_flags, const char *name, void *data)
{
        struct file_system_type *type;
	struct fs_context *fc;
        ...
        // 获取文件系统类型，通过遍历`file_systems`列表获取匹配的文件系统类型
        type = get_fs_type(fstype);
        if (!type) return -ENODEV;
        ...
        // 创建文件系统上下文
        fc = fs_context_for_mount(type, sb_flags);
        if (IS_ERR(fc)) return PTR_ERR(fc);

        ...
        fc->oldapi = true;

        // 解析挂载选项
	if (subtype) err = vfs_parse_fs_string(fc, "subtype", subtype);
	if (!err && name) err = vfs_parse_fs_string(fc, "source", name);
	if (!err) err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc)) err = -EPERM;
        // 创建新的挂载点
	if (!err) err = do_new_mount_fc(fc, path, mnt_flags);

	put_fs_context(fc);
	return err;
}
```

* 创建文件系统上下文

`fs_context_for_mount`函数创建挂载使用的文件系统上下文，该函数是对`alloc_fs_context`函数的封装，创建并初始化文件系统上下文，如下：

```c
// file: fs/fs_context.c
struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
					unsigned int sb_flags)
{
	return alloc_fs_context(fs_type, NULL, sb_flags, 0,
					FS_CONTEXT_FOR_MOUNT);
}

static struct fs_context *alloc_fs_context(struct file_system_type *fs_type,
				      struct dentry *reference,
				      unsigned int sb_flags,
				      unsigned int sb_flags_mask,
				      enum fs_context_purpose purpose)
{
	int (*init_fs_context)(struct fs_context *);
	struct fs_context *fc;
	int ret = -ENOMEM;

        // 分配文件系统上下文结构体
	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
	if (!fc) return ERR_PTR(-ENOMEM);

        // 初始化文件系统上下文结构体
	fc->purpose	= purpose;
	fc->sb_flags	= sb_flags;
	fc->sb_flags_mask = sb_flags_mask;
	fc->fs_type	= get_filesystem(fs_type);
	fc->cred	= get_current_cred();
	fc->net_ns	= get_net(current->nsproxy->net_ns);
	fc->log.prefix	= fs_type->name;

	mutex_init(&fc->uapi_mutex);

        // 初始化用户命名空间
	switch (purpose) {
	case FS_CONTEXT_FOR_MOUNT:
		fc->user_ns = get_user_ns(fc->cred->user_ns);
		break;
	case FS_CONTEXT_FOR_SUBMOUNT:
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		break;
	case FS_CONTEXT_FOR_RECONFIGURE:
		atomic_inc(&reference->d_sb->s_active);
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		fc->root = dget(reference);
		break;
	}

        // 获取初始化接口
	init_fs_context = fc->fs_type->init_fs_context;
	if (!init_fs_context) init_fs_context = legacy_init_fs_context;

        // 初始化文件系统上下文
	ret = init_fs_context(fc);
	if (ret < 0) goto err_fc;
	fc->need_free = true;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}
```

* 解析挂载选项

`vfs_parse_fs_string`函数最终调用`vfs_parse_fs_param`解析挂载选项中的字符串参数，如下：

```c
// file: include/linux/fs_context.h
static inline int vfs_parse_fs_string(struct fs_context *fc, const char *key,
			       const char *value)
{
	return vfs_parse_fs_qstr(fc, key, value ? &QSTR(value) : NULL);
}
// file: fs/fs_context.c
int vfs_parse_fs_qstr(struct fs_context *fc, const char *key, const struct qstr *value)
{
	struct fs_parameter param = {
		.key	= key,
		.type	= fs_value_is_flag,
		.size	= value ? value->len : 0,
	};

	if (value) {
		param.string = kmemdup_nul(value->name, value->len, GFP_KERNEL);
		if (!param.string) return -ENOMEM;
		param.type = fs_value_is_string;
	}

	ret = vfs_parse_fs_param(fc, &param);
	kfree(param.string);
	return ret;
}
```

`vfs_parse_fs_param`函数可调用`parse_param`接口，解析挂载选项中的参数，如下：

```c
// file: fs/fs_context.c
int vfs_parse_fs_param(struct fs_context *fc, struct fs_parameter *param)
{
        ...
        // 调用文件系统上下文的parse_param接口解析参数
	if (fc->ops->parse_param) {
		ret = fc->ops->parse_param(fc, param);
		if (ret != -ENOPARAM) return ret;
	}
        ...
}
```

* 添加挂载

`do_new_mount_fc`函数在获取到superblock后，添加到文件系统命名空间中，如下：

```c
// file: fs/namespace.c
static int do_new_mount_fc(struct fs_context *fc, const struct path *mountpoint,
			   unsigned int mnt_flags)
{
	struct super_block *sb;
        // 获取vfs挂载点
	struct vfsmount *mnt __free(mntput) = fc_mount(fc);
	int error;

	if (IS_ERR(mnt)) return PTR_ERR(mnt);
        // 获取superblock
	sb = fc->root->d_sb;
	error = security_sb_kern_mount(sb);
	if (unlikely(error)) return error;

	if (unlikely(mount_too_revealing(sb, &mnt_flags))) { ... }

	mnt_warn_timestamp_expiry(mountpoint, mnt);

	LOCK_MOUNT(mp, mountpoint);
        // 添加挂载点到文件系统命名空间
	error = do_add_mount(real_mount(mnt), &mp, mnt_flags);
	if (!error) retain_and_null_ptr(mnt); // consumed on success
	return error;
}
```

`fc_mount` 通过`vfs_get_tree`获取root后创建`vfsmount`挂载点，如下：

```c
// file: fs/namespace.c
struct vfsmount *fc_mount(struct fs_context *fc)
{       
        // 获取文件系统树
	int err = vfs_get_tree(fc);
	if (!err) {
		up_write(&fc->root->d_sb->s_umount);
                // 创建vfsmount挂载点
		return vfs_create_mount(fc);
	}
	return ERR_PTR(err);
}
```

`vfs_get_tree`函数获取文件系统的superblock，如下：

```c
// file: fs/namespace.c
int vfs_get_tree(struct fs_context *fc)
{
	struct super_block *sb;
	int error;

	if (fc->root) return -EBUSY;

        // 调用文`get_tree`接口获取文件系统树
	error = fc->ops->get_tree(fc);
	if (error < 0) return error;
        ...

	if (!fc->root) { ... }

        sb = fc->root->d_sb;
	WARN_ON(!sb->s_bdi);
	super_wake(sb, SB_BORN);

	error = security_sb_set_mnt_opts(sb, fc->security, 0, NULL);
	if (unlikely(error)) { ... }
        ...
	return 0;
}
```

##### (2) `fuse`/`fuseblk`文件系统的接口

用户空间通过`mount`系统调用挂载`fuse`文件系统时，支持文件系统的类型为`fuse`或`fuseblk`，这两个文件系统通过`module`的方式加载，如下：

```c
// file: fs/fuse/inode.c
static int __init fuse_init(void)
{
	int res;
        ...
        // 初始化FUSE连接列表
	INIT_LIST_HEAD(&fuse_conn_list);
        // 初始化FUSE文件系统
	res = fuse_fs_init();
	if (res) goto err;
        // 初始化FUSE设备文件
	res = fuse_dev_init();
	if (res) goto err_fs_cleanup;

	res = fuse_sysfs_init();
	if (res) goto err_dev_cleanup;

	res = fuse_ctl_init();
	if (res) goto err_sysfs_cleanup;

	fuse_dentry_tree_init();

	sanitize_global_limit(&max_user_bgreq);
	sanitize_global_limit(&max_user_congthresh);
	return 0;
        ...
}

static void __exit fuse_exit(void)
{
	pr_debug("exit\n");

	fuse_dentry_tree_cleanup();
	fuse_ctl_cleanup();
	fuse_sysfs_cleanup();
	fuse_fs_cleanup();
	fuse_dev_cleanup();
}
module_init(fuse_init);
module_exit(fuse_exit);
```

可以看到，`/dev/fuse`设备文件也是在此阶段通过`fuse_dev_init`函数初始化的。`fuse_fs_init`注册`fuse`和`fuseblk`文件系统，如下：

```c
// file: fs/fuse/inode.c
static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.fs_flags	= FS_HAS_SUBTYPE | FS_USERNS_MOUNT | FS_ALLOW_IDMAP,
	.init_fs_context = fuse_init_fs_context,
	.parameters	= fuse_fs_parameters,
	.kill_sb	= fuse_kill_sb_anon,
};
MODULE_ALIAS_FS("fuse");

static struct file_system_type fuseblk_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuseblk",
	.init_fs_context = fuse_init_fs_context,
	.parameters	= fuse_fs_parameters,
	.kill_sb	= fuse_kill_sb_blk,
	.fs_flags	= FS_REQUIRES_DEV | FS_HAS_SUBTYPE | FS_ALLOW_IDMAP,
};
MODULE_ALIAS_FS("fuseblk");

static int __init fuse_fs_init(void)
{
	int err;
        // 创建FUSE inode缓存
	fuse_inode_cachep = kmem_cache_create("fuse_inode",
			sizeof(struct fuse_inode), 0,
			SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT,
			fuse_inode_init_once);
	err = -ENOMEM;
	if (!fuse_inode_cachep) goto out;

        // 注册FUSE块设备文件系统
	err = register_fuseblk();
	if (err) goto out2;
        // 注册FUSE文件系统
	err = register_filesystem(&fuse_fs_type);
	if (err) goto out3;
        // 注册FUSE系统控制接口
	err = fuse_sysctl_register();
	if (err) goto out4;
	return 0;
        ...
}
```

结合上一小节对`mount`系统调用的分析，我们继续分析`fuse`或`fuseblk`文件系统的挂载过程。以`fuse`文件系统为例，如下：

* 初始化上下文

`.init_fs_context`接口用于初始化文件系统上下文，改接口设置为`fuse_init_fs_context`用于初始化FUSE文件系统的上下文，如下：

```c
// file: fs/fuse/inode.c
static int fuse_init_fs_context(struct fs_context *fsc)
{
	struct fuse_fs_context *ctx;

        // 分配FUSE文件系统上下文
	ctx = kzalloc(sizeof(struct fuse_fs_context), GFP_KERNEL);
	if (!ctx) return -ENOMEM;

	ctx->max_read = ~0;
	ctx->blksize = FUSE_DEFAULT_BLKSIZE;
	ctx->legacy_opts_show = true;

#ifdef CONFIG_BLOCK
	if (fsc->fs_type == &fuseblk_fs_type) {
		ctx->is_bdev = true;
		ctx->destroy = true;
	}
#endif

        // 设置FUSE文件系统上下文
	fsc->fs_private = ctx;
        // 设置FUSE文件系统上下文操作接口
	fsc->ops = &fuse_context_ops;
	return 0;
}
```

`fuse_context_ops`是FUSE文件系统上下文操作接口，如下：

```c
// file: fs/fuse/inode.c
static const struct fs_context_operations fuse_context_ops = {
	.free		= fuse_free_fsc,
	.parse_param	= fuse_parse_param,
	.reconfigure	= fuse_reconfigure,
	.get_tree	= fuse_get_tree,
};
```

* 解析挂载参数

`.parse_param`接口用于解析挂载参数，如下：

```c
// file: fs/fuse/inode.c
static int fuse_parse_param(struct fs_context *fsc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct fuse_fs_context *ctx = fsc->fs_private;
        ...
        // 解析挂载参数
	opt = fs_parse(fsc, fuse_fs_parameters, param, &result);
	if (opt < 0) return opt;
}
```

`fuse_fs_parameters`是FUSE文件系统支持的挂载参数，如下：

```c
// file: fs/fuse/inode.c
static const struct fs_parameter_spec fuse_fs_parameters[] = {
	fsparam_string	("source",		OPT_SOURCE),
	fsparam_u32	("fd",			OPT_FD),
	fsparam_u32oct	("rootmode",		OPT_ROOTMODE),
	fsparam_uid	("user_id",		OPT_USER_ID),
	fsparam_gid	("group_id",		OPT_GROUP_ID),
	fsparam_flag	("default_permissions",	OPT_DEFAULT_PERMISSIONS),
	fsparam_flag	("allow_other",		OPT_ALLOW_OTHER),
	fsparam_u32	("max_read",		OPT_MAX_READ),
	fsparam_u32	("blksize",		OPT_BLKSIZE),
	fsparam_string	("subtype",		OPT_SUBTYPE),
	{}
};
```

* 获取根节点

`.get_tree`接口用于获取根节点，设置为`fuse_get_tree`，其实现如下：

```c
// file: fs/fuse/inode.c
static int fuse_get_tree(struct fs_context *fsc)
{
	struct fuse_fs_context *ctx = fsc->fs_private;
	struct fuse_dev *fud;
	struct fuse_conn *fc;
	struct fuse_mount *fm;
	struct super_block *sb;
	int err;

        // 分配FUSE连接上下文
	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if (!fc) return -ENOMEM;

        // 分配FUSE挂载上下文
	fm = kzalloc(sizeof(*fm), GFP_KERNEL);
	if (!fm) { ... }

        // 初始化FUSE连接上下文
	fuse_conn_init(fc, fm, fsc->user_ns, &fuse_dev_fiq_ops, NULL);
	fc->release = fuse_free_conn;

        // 设置FUSE文件系统信息
	fsc->s_fs_info = fm;

        // 用户指定文件描述符时，获取文件描述符对应的文件结构体
	if (ctx->fd_present)
		ctx->file = fget(ctx->fd);

        // 处理块设备挂载
	if (IS_ENABLED(CONFIG_BLOCK) && ctx->is_bdev) {
		err = get_tree_bdev(fsc, fuse_fill_super);
		goto out;
	}

	err = -EINVAL;
	if (!ctx->file) goto out;

        // 获取FUSE设备，
	fud = __fuse_get_dev(ctx->file);
	if (ctx->file->f_op == &fuse_dev_operations && fud) {
		fsc->sget_key = fud->fc;
                // 已经初始化时，使用已有的FUSE连接上下文
		sb = sget_fc(fsc, fuse_test_super, fuse_set_no_super);
		err = PTR_ERR_OR_ZERO(sb);
		if (!IS_ERR(sb))
			fsc->root = dget(sb->s_root);
	} else {
                // 未初始化时，获取新的FUSE连接上下文
		err = get_tree_nodev(fsc, fuse_fill_super);
	}
out:
	if (fsc->s_fs_info)
		fuse_mount_destroy(fm);
	if (ctx->file)
		fput(ctx->file);
	return err;
}
```

`get_tree_nodev`获取新的FUSE连接上下文，使用`vfs_get_super`填充超级块，如下：

```c
// file: fs/super.c
int get_tree_nodev(struct fs_context *fc,
		  int (*fill_super)(struct super_block *sb,
				    struct fs_context *fc))
{
	return vfs_get_super(fc, NULL, fill_super);
}
static int vfs_get_super(struct fs_context *fc,
		int (*test)(struct super_block *, struct fs_context *),
		int (*fill_super)(struct super_block *sb,
				  struct fs_context *fc))
{
	struct super_block *sb;
	int err;

        // 获取或者创建新的超级块
	sb = sget_fc(fc, test, set_anon_super_fc);
	if (IS_ERR(sb)) return PTR_ERR(sb);

	if (!sb->s_root) {
                // 填充超级块
		err = fill_super(sb, fc);
		if (err) goto error;

		sb->s_flags |= SB_ACTIVE;
	}
        // 设置根节点
	fc->root = dget(sb->s_root);
	return 0;

error:
	deactivate_locked_super(sb);
	return err;
}
```

`fuse_fill_super`函数是FUSE设置填充超级块的回调函数，核心的调用过程如下：

```c
// file: fs/fuse/inode.c
static int fuse_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct fuse_fs_context *ctx = fsc->fs_private;
	struct fuse_mount *fm;
	int err;

        // 检查挂载参数是否完整
	if (!ctx->file || !ctx->rootmode_present ||
	    !ctx->user_id_present || !ctx->group_id_present)
		return -EINVAL;

        // 检查文件操作是否为FUSE设备操作，且用户命名空间是否匹配
	if ((ctx->file->f_op != &fuse_dev_operations) ||
	    (ctx->file->f_cred->user_ns != sb->s_user_ns))
		return -EINVAL;
	ctx->fudptr = &ctx->file->private_data;
        // 填充超级块
	err = fuse_fill_super_common(sb, ctx);
	if (err) return err;
        // 内存屏障，确保前面的写操作完成，对其他CPU可见
	smp_mb();
        // 获取FUSE挂载上下文
	fm = get_fuse_mount_super(sb);
        // 发送初始化请求
	return fuse_send_init(fm);
}
```

`fuse_fill_super_common`函数是FUSE填充超级块的核心操作，主要操作有：

1. 填充超级块`ops`操作接口并创建根目录；
2. 设置fuse连接的参数；

其实现如下：

```c
// file: fs/fuse/inode.c
int fuse_fill_super_common(struct super_block *sb, struct fuse_fs_context *ctx)
{
	struct fuse_dev *fud = NULL;
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct inode *root;
	struct dentry *root_dentry;
	int err;

	err = -EINVAL;
	if (sb->s_flags & SB_MANDLOCK) goto err;

	rcu_assign_pointer(fc->curr_bucket, fuse_sync_bucket_alloc());
	// 设置FUSE超级块默认参数
	fuse_sb_defaults(sb);

	if (ctx->is_bdev) {
#ifdef CONFIG_BLOCK
		err = -EINVAL;
		if (!sb_set_blocksize(sb, ctx->blksize)) goto err;
#endif
		fc->sync_fs = 1;
	} else {
		// 设置默认块大小为页面大小
		sb->s_blocksize = PAGE_SIZE;
		sb->s_blocksize_bits = PAGE_SHIFT;
	}

	sb->s_subtype = ctx->subtype;
	ctx->subtype = NULL;
	if (IS_ENABLED(CONFIG_FUSE_DAX)) {
		err = fuse_dax_conn_alloc(fc, ctx->dax_mode, ctx->dax_dev);
		if (err) goto err;
	}

	if (ctx->fudptr) {
		err = -ENOMEM;
		// 分配并安装FUSE设备
		fud = fuse_dev_alloc_install(fc);
		if (!fud) goto err_free_dax;
	}

	fc->dev = sb->s_dev;
	fm->sb = sb;
	err = fuse_bdi_init(fc, sb);
	if (err) goto err_dev_free;

	/* Handle umasking inside the fuse code */
	if (sb->s_flags & SB_POSIXACL)
		fc->dont_mask = 1;
	sb->s_flags |= SB_POSIXACL;

	// 设置FUSE连接上下文参数
	fc->default_permissions = ctx->default_permissions;
	fc->allow_other = ctx->allow_other;
	fc->user_id = ctx->user_id;
	fc->group_id = ctx->group_id;
	fc->legacy_opts_show = ctx->legacy_opts_show;
	fc->max_read = max_t(unsigned int, 4096, ctx->max_read);
	fc->destroy = ctx->destroy;
	fc->no_control = ctx->no_control;
	fc->no_force_umount = ctx->no_force_umount;

	err = -ENOMEM;
	// 获取根目录节点
	root = fuse_get_root_inode(sb, ctx->rootmode);
	// 设置默认目录操作符
	set_default_d_op(sb, &fuse_dentry_operations);
	// 创建根目录
	root_dentry = d_make_root(root);
	if (!root_dentry) goto err_dev_free;

	mutex_lock(&fuse_mutex);
	err = -EINVAL;
	if (ctx->fudptr && *ctx->fudptr) {
		// 检查FUSE设备指针是否为同步初始化
		if (*ctx->fudptr == FUSE_DEV_SYNC_INIT)
			fc->sync_init = 1;
		else
			goto err_unlock;
	}
	// 添加FUSE连接上下文到连接列表
	err = fuse_ctl_add_conn(fc);
	if (err) goto err_unlock;
	// 将FUSE连接上下文添加到连接列表
	list_add_tail(&fc->entry, &fuse_conn_list);
	sb->s_root = root_dentry;
	if (ctx->fudptr) {
		// 修改FUSE设备指针，指向新分配的设备，并唤醒等待队列
		*ctx->fudptr = fud;
		wake_up_all(&fuse_dev_waitq);
	}
	mutex_unlock(&fuse_mutex);
	return 0;

 err_unlock:
	mutex_unlock(&fuse_mutex);
	dput(root_dentry);
 err_dev_free:
	if (fud) fuse_dev_free(fud);
 err_free_dax:
	if (IS_ENABLED(CONFIG_FUSE_DAX))
		fuse_dax_conn_free(fc);
 err:
	return err;
}
```

`set_default_d_op`函数设置FUSE超级块的默认目录操作接口，如下：

```c
// file: fs/fuse/inode.c
void set_default_d_op(struct super_block *s, const struct dentry_operations *ops)
{
	unsigned int flags = d_op_flags(ops);
	s->__s_d_op = ops;
	s->s_d_flags = (s->s_d_flags & ~DCACHE_OP_FLAGS) | flags;
}
```

`fuse_dentry_operations`是FUSE文件系统的默认的目录操作接口，定义如下：

```c
// file: fs/fuse/dir.c
const struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
	.d_delete	= fuse_dentry_delete,
	.d_init		= fuse_dentry_init,
	.d_prune	= fuse_dentry_prune,
	.d_release	= fuse_dentry_release,
	.d_automount	= fuse_dentry_automount,
};
```

##### (3) `fuse`获取根目录的过程

在填充超级块时，`fuse_sb_defaults`函数会设置FUSE超级块的默认参数，包括块大小、子类型等。如下:

```c
// file: fs/fuse/inode.c
static void fuse_sb_defaults(struct super_block *sb)
{
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_xattr = fuse_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_export_op = &fuse_export_operations;
	sb->s_iflags |= SB_I_IMA_UNVERIFIABLE_SIGNATURE;
	sb->s_iflags |= SB_I_NOIDMAP;
	if (sb->s_user_ns != &init_user_ns)
		sb->s_iflags |= SB_I_UNTRUSTED_MOUNTER;
	sb->s_flags &= ~(SB_NOSEC | SB_I_VERSION);
}
```

`fuse`文件系统的标识为`FUSE_SUPER_MAGIC`，定义如下：

```c
// file: include/uapi/linux/magic.h
#define FUSE_SUPER_MAGIC 0x65735546
```

对应的操作接口设置为`fuse_super_operations`, 定义如下：

```c
// file: fs/fuse/inode.c
static const struct super_operations fuse_super_operations = {
	.alloc_inode    = fuse_alloc_inode,
	.free_inode     = fuse_free_inode,
	.evict_inode	= fuse_evict_inode,
	.write_inode	= fuse_write_inode,
	.drop_inode	= inode_just_drop,
	.umount_begin	= fuse_umount_begin,
	.statfs		= fuse_statfs,
	.sync_fs	= fuse_sync_fs,
	.show_options	= fuse_show_options,
};
```

在设置FUSE超级块默认参数后，会调用`fuse_get_root_inode`函数获取根目录节点。其实现如下：

```c
// file: fs/fuse/inode.c
static struct inode *fuse_get_root_inode(struct super_block *sb, unsigned int mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));
	// 设置根目录节点的权限模式
	attr.mode = mode;
	attr.ino = FUSE_ROOT_ID;
	attr.nlink = 1;
	// 获取inode节点
	return fuse_iget(sb, FUSE_ROOT_ID, 0, &attr, 0, 0, 0);
}
```

`fuse_iget`函数会根据inodeid获取对应的inode节点。如果节点不存在，则会创建一个新的节点。其实现如下：

```c
// file: fs/fuse/inode.c
struct inode *fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version,
			u64 evict_ctr)
{
	struct inode *inode;
	struct fuse_inode *fi;
	struct fuse_conn *fc = get_fuse_conn_super(sb);

	// 自动挂载的子目录节点，不添加到inode hash表中
	if (fc->auto_submounts && (attr->flags & FUSE_ATTR_SUBMOUNT) &&
	    S_ISDIR(attr->mode)) {
		struct fuse_inode *fi;
		// 创建新的目录节点
		inode = new_inode(sb);
		if (!inode) return NULL;
		// 初始化新创建的目录节点
		fuse_init_inode(inode, attr, fc);
		fi = get_fuse_inode(inode);
		fi->nodeid = nodeid;
		fi->submount_lookup = fuse_alloc_submount_lookup();
		if (!fi->submount_lookup) {
			iput(inode);
			return NULL;
		}
		// 初始化子挂载查找表
		fuse_init_submount_lookup(fi->submount_lookup, nodeid);
		inode->i_flags |= S_AUTOMOUNT;
		goto done;
	}

retry:
	// 获取或创建新的inode节点
	inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);
	if (!inode) return NULL;

	if ((inode_state_read_once(inode) & I_NEW)) {
		inode->i_flags |= S_NOATIME;
		if (!fc->writeback_cache || !S_ISREG(attr->mode))
			inode->i_flags |= S_NOCMTIME;
		inode->i_generation = generation;
		// 初始化新创建的inode节点
		fuse_init_inode(inode, attr, fc);
		unlock_new_inode(inode);
	} else if (fuse_stale_inode(inode, generation, attr)) {
		// 标记旧的inode节点为无效
		fuse_make_bad(inode);
		if (inode != d_inode(sb->s_root)) {
			remove_inode_hash(inode);
			iput(inode);
			goto retry;
		}
	}
	fi = get_fuse_inode(inode);
	spin_lock(&fi->lock);
	fi->nlookup++;
	spin_unlock(&fi->lock);
done:
	// 更新inode节点的属性
	fuse_change_attributes_i(inode, attr, NULL, attr_valid, attr_version,
				 evict_ctr);
	return inode;
}
```

* 创建新的inode节点

`new_inode` 函数会创建一个新的inode节点。其实现如下：

```c
// file: fs/inode.c
struct inode *new_inode(struct super_block *sb)
{
	struct inode *inode;
	// 分配新的inode节点
	inode = alloc_inode(sb);
	if (inode) inode_sb_list_add(inode);
	return inode;
}
// file: fs/inode.c
struct inode *alloc_inode(struct super_block *sb)
{
	const struct super_operations *ops = sb->s_op;
	struct inode *inode;
	// 调用`.alloc_inode`接口分配新的inode节点
	if (ops->alloc_inode)
		inode = ops->alloc_inode(sb);
	else
		inode = alloc_inode_sb(sb, inode_cachep, GFP_KERNEL);

	if (!inode) return NULL;

	// 初始化新分配的inode节点
	if (unlikely(inode_init_always(sb, inode))) {
		// 调用`.destroy_inode`接口销毁无效的inode节点	
		if (ops->destroy_inode) {
			ops->destroy_inode(inode);
			if (!ops->free_inode)
				return NULL;
		}
		inode->free_inode = ops->free_inode;
		i_callback(&inode->i_rcu);
		return NULL;
	}
	return inode;
}
```

fuse超级块通过设置的`.alloc_inode`接口分配新的inode节点，其设置为`fuse_alloc_inode`, 其实现如下：

```c
// file: fs/fuse/inode.c
static struct inode *fuse_alloc_inode(struct super_block *sb)
{
	struct fuse_inode *fi;
	// 分配新的fuse_inode节点
	fi = alloc_inode_sb(sb, fuse_inode_cachep, GFP_KERNEL);
	if (!fi) return NULL;

	// 初始化新分配的fuse_inode节点的私有数据
	BUILD_BUG_ON(offsetof(struct fuse_inode, inode) != 0);
	memset((void *) fi + sizeof(fi->inode), 0, sizeof(*fi) - sizeof(fi->inode));

	fi->inval_mask = ~0;
	mutex_init(&fi->mutex);
	spin_lock_init(&fi->lock);
	// 分配新的forget结构体
	fi->forget = fuse_alloc_forget();
	if (!fi->forget) goto out_free;

	if (IS_ENABLED(CONFIG_FUSE_DAX) && !fuse_dax_inode_alloc(sb, fi))
		goto out_free_forget;

	if (IS_ENABLED(CONFIG_FUSE_PASSTHROUGH))
		fuse_inode_backing_set(fi, NULL);

	return &fi->inode;

out_free_forget:
	kfree(fi->forget);
out_free:
	kmem_cache_free(fuse_inode_cachep, fi);
	return NULL;
}
```

* 初始化fuse_inode节点

在新创建fuse_inode节点后，通过`fuse_init_inode`函数进行初始化，根据mode初始化不同的节点类型。如下：

```c
// file: fs/fuse/inode.c
static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr,
			    struct fuse_conn *fc)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	inode_set_mtime(inode, attr->mtime, attr->mtimensec);
	inode_set_ctime(inode, attr->ctime, attr->ctimensec);
	if (S_ISREG(inode->i_mode)) {
		// 初始化普通文件节点
		fuse_init_common(inode);
		fuse_init_file_inode(inode, attr->flags);
	} else if (S_ISDIR(inode->i_mode))
		// 初始化目录节点
		fuse_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		// 初始化符号链接节点
		fuse_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		// 初始化字符设备、块设备、FIFO节点、套接字节点
		fuse_init_common(inode);
		init_special_inode(inode, inode->i_mode, new_decode_dev(attr->rdev));
	} else
		BUG();
	 // 如果不支持POSIX ACL，则缓存ACL
	if (!fc->posix_acl)
		inode->i_acl = inode->i_default_acl = ACL_DONT_CACHE;
}
```

* 普通文件节点的初始化

`fuse_init_common`函数用于初始化普通文件节点的公共部分，设置`.i_op`，如下：

```c
// file: fs/fuse/dir.c
void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}
```

`.i_op`设置为`fuse_common_inode_operations`，其定义如下：

```c
// file: fs/fuse/dir.c
static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
	.get_inode_acl	= fuse_get_inode_acl,
	.get_acl	= fuse_get_acl,
	.set_acl	= fuse_set_acl,
	.fileattr_get	= fuse_fileattr_get,
	.fileattr_set	= fuse_fileattr_set,
};
```

`fuse_init_file_inode`函数用于设置普通文件节点，设置`.i_fop`和`.i_data.a_ops`, 如下：

```c
// file: fs/fuse/file.c
void fuse_init_file_inode(struct inode *inode, unsigned int flags)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);

	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
	if (fc->writeback_cache)
		mapping_set_writeback_may_deadlock_on_reclaim(&inode->i_data);

	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	fi->writectr = 0;
	fi->iocachectr = 0;
	init_waitqueue_head(&fi->page_waitq);
	init_waitqueue_head(&fi->direct_io_waitq);

	if (IS_ENABLED(CONFIG_FUSE_DAX))
		fuse_dax_inode_init(inode, flags);
}
```

`.i_fop`设置为`fuse_file_operations`，其定义如下：

```c
// file: fs/fuse/file.c
static const struct file_operations fuse_file_operations = {
	.llseek		= fuse_file_llseek,
	.read_iter	= fuse_file_read_iter,
	.write_iter	= fuse_file_write_iter,
	.mmap		= fuse_file_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
	.get_unmapped_area = thp_get_unmapped_area,
	.flock		= fuse_file_flock,
	.splice_read	= fuse_splice_read,
	.splice_write	= fuse_splice_write,
	.unlocked_ioctl	= fuse_file_ioctl,
	.compat_ioctl	= fuse_file_compat_ioctl,
	.poll		= fuse_file_poll,
	.fallocate	= fuse_file_fallocate,
	.copy_file_range = fuse_copy_file_range,
};
```

* 目录文件节点的初始化

`fuse_init_dir`函数用于设置目录节点，设置`.i_op`和`.i_fop`, 如下：

```c
// file: fs/fuse/dir.c
void fuse_init_dir(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;

	spin_lock_init(&fi->rdc.lock);
	fi->rdc.cached = false;
	fi->rdc.size = 0;
	fi->rdc.pos = 0;
	fi->rdc.version = 0;
}
```

`.i_op`设置为`fuse_dir_inode_operations`，如下：

```c
// file: fs/fuse/dir.c
static const struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename2,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.atomic_open	= fuse_atomic_open,
	.tmpfile	= fuse_tmpfile,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
	.get_inode_acl	= fuse_get_inode_acl,
	.get_acl	= fuse_get_acl,
	.set_acl	= fuse_set_acl,
	.fileattr_get	= fuse_fileattr_get,
	.fileattr_set	= fuse_fileattr_set,
};
```

`.i_fop`设置为`fuse_dir_operations`，如下：

```c
// file: fs/fuse/dir.c
static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
	.unlocked_ioctl	= fuse_dir_ioctl,
	.compat_ioctl	= fuse_dir_compat_ioctl,
	.setlease	= simple_nosetlease,
};
```

* 符号链接节点的初始化

`fuse_init_symlink`函数用于设置符号链接节点，设置`.i_op`和`.i_data.a_ops`, 如下：

```c
// file: fs/fuse/dir.c
void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
	inode->i_data.a_ops = &fuse_symlink_aops;
	inode_nohighmem(inode);
}
```

`.i_op`设置为`fuse_symlink_inode_operations`，其定义如下：

```c
// file: fs/fuse/dir.c
static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.get_link	= fuse_get_link,
	.getattr	= fuse_getattr,
	.listxattr	= fuse_listxattr,
};
```

* 特殊节点的初始化

`init_special_inode`函数用于设置特殊节点，设置`.i_op`和`.i_fop`, 如下：

```c
// file: fs/fuse/dir.c
void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
	inode->i_mode = mode;
	switch (inode->i_mode & S_IFMT) {
	case S_IFCHR:
		inode->i_fop = &def_chr_fops;
		inode->i_rdev = rdev;
		break;
	case S_IFBLK:
		if (IS_ENABLED(CONFIG_BLOCK))
			inode->i_fop = &def_blk_fops;
		inode->i_rdev = rdev;
		break;
	case S_IFIFO:
		inode->i_fop = &pipefifo_fops;
		break;
	case S_IFSOCK:
		/* leave it no_open_fops */
		break;
	default:
		printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o) for"
				  " inode %s:%lu\n", mode, inode->i_sb->s_id,
				  inode->i_ino);
		break;
	}
}
```

### 3.3 `fuse`文件系统交互过程

在挂载`fuse`文件系统时，填充超级块之后会调用`fuse_send_init`函数向用户空间发送`FUSE_INIT`请求，如下：

```c
// file: fs/fuse/inode.c
int fuse_send_init(struct fuse_mount *fm)
{
	// 创建FUSE_INIT请求参数
	struct fuse_init_args *ia = fuse_new_init(fm);
	int err;

	if (fm->fc->sync_init) {
		// 同步发送FUSE_INIT请求
		err = fuse_simple_request(fm, &ia->args);
		if (err > 0) err = 0;
	} else {
		// 异步发送FUSE_INIT请求
		ia->args.end = process_init_reply;
		err = fuse_simple_background(fm, &ia->args, GFP_KERNEL);
		if (!err) return 0;
	}
	// 处理FUSE_INIT回复
	process_init_reply(fm, &ia->args, err);
	if (fm->fc->conn_error) return -ENOTCONN;
	return 0;
}
```

接下来，我们以发送`FUSE_INIT`请求为例，说明`fuse_send_init`函数的工作原理。

#### 3.3.1 内核空间创建`FUSE`请求参数

`fuse_new_init`函数用于创建`FUSE_INIT`请求参数，如下：

```c
// file: fs/fuse/inode.c
static struct fuse_init_args *fuse_new_init(struct fuse_mount *fm)
{
	struct fuse_init_args *ia;
	u64 flags;

	// 分配FUSE_INIT请求参数内存
	ia = kzalloc(sizeof(*ia), GFP_KERNEL | __GFP_NOFAIL);
	// 设置FUSE_INIT请求参数版本
	ia->in.major = FUSE_KERNEL_VERSION;
	ia->in.minor = FUSE_KERNEL_MINOR_VERSION;
	ia->in.max_readahead = fm->sb->s_bdi->ra_pages * PAGE_SIZE;
	...
	if (fm->fc->auto_submounts)
		flags |= FUSE_SUBMOUNTS;
	if (IS_ENABLED(CONFIG_FUSE_PASSTHROUGH))
		flags |= FUSE_PASSTHROUGH;

	if (fuse_uring_enabled())
		flags |= FUSE_OVER_IO_URING;

	ia->in.flags = flags;
	ia->in.flags2 = flags >> 32;
	// 设置FUSE_INIT请求参数，设置操作码为FUSE_INIT
	ia->args.opcode = FUSE_INIT;
	// 设置FUSE_INIT请求参数
	ia->args.in_numargs = 1;
	ia->args.in_args[0].size = sizeof(ia->in);
	ia->args.in_args[0].value = &ia->in;
	// 设置FUSE_INIT请求参数输出参数数量
	ia->args.out_numargs = 1;
	ia->args.out_argvar = true;
	ia->args.out_args[0].size = sizeof(ia->out);
	ia->args.out_args[0].value = &ia->out;
	ia->args.force = true;
	ia->args.nocreds = true;

	return ia;
}
```

`struct fuse_init_args`是`FUSE_INIT`请求参数结构体，定义如下：

```c
// file: fs/fuse/inode.c
struct fuse_init_args {
	struct fuse_args args;
	struct fuse_init_in in;
	struct fuse_init_out out;
};
```

可以看到`fuse_new_init`函数设置`struct fuse_args`的操作码为`FUSE_INIT`，并设置了输入参数为`ia->in`，输出参数为`ia->out`。

`struct fuse_args`是`FUSE`请求参数结构体，定义如下：

```c
// file: fs/fuse/fuse_i.h
struct fuse_args {
	uint64_t nodeid;
	uint32_t opcode;
	uint8_t in_numargs;
	uint8_t out_numargs;
	uint8_t ext_idx;
	bool force:1;
	bool noreply:1;
	bool nocreds:1;
	bool in_pages:1;
	bool out_pages:1;
	bool user_pages:1;
	bool out_argvar:1;
	bool page_zeroing:1;
	bool page_replace:1;
	bool may_block:1;
	bool is_ext:1;
	bool is_pinned:1;
	bool invalidate_vmap:1;
	// 输入参数
	struct fuse_in_arg in_args[4];
	// 输出参数
	struct fuse_arg out_args[2];
	void (*end)(struct fuse_mount *fm, struct fuse_args *args, int error);
	/* Used for kvec iter backed by vmalloc address */
	void *vmap_base;
};
```

#### 3.3.2 内核空间初始化`FUSE`请求

我们以同步发送`FUSE_INIT`请求为例，`fuse_simple_request`函数用于发送fuse请求，是对`__fuse_simple_request`函数的封装，如下：

```c
// file: fs/fuse/fuse_i.h
static inline ssize_t fuse_simple_request(struct fuse_mount *fm, struct fuse_args *args)
{
	return __fuse_simple_request(&invalid_mnt_idmap, fm, args);
}
// file: fs/fuse/dev.c
ssize_t __fuse_simple_request(struct mnt_idmap *idmap,
			      struct fuse_mount *fm,
			      struct fuse_args *args)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_req *req;
	ssize_t ret;

	if (args->force) {
		atomic_inc(&fc->num_waiting);
		// 分配FUSE请求
		req = fuse_request_alloc(fm, GFP_KERNEL | __GFP_NOFAIL);
		if (!args->nocreds) fuse_force_creds(req);
		__set_bit(FR_WAITING, &req->flags);
		__set_bit(FR_FORCE, &req->flags);
	} else {
		WARN_ON(args->nocreds);
		// 获取FUSE请求
		req = fuse_get_req(idmap, fm, false);
		if (IS_ERR(req)) return PTR_ERR(req);
	}
	// 调整FUSE请求兼容性
	fuse_adjust_compat(fc, args);
	// 将FUSE请求参数转换为FUSE请求
	fuse_args_to_req(req, args);

	if (!args->noreply) __set_bit(FR_ISREPLY, &req->flags);
	// 发送FUSE请求
	__fuse_request_send(req);
	// 检查FUSE请求回复是否有错误
	ret = req->out.h.error;
	if (!ret && args->out_argvar) {
		BUG_ON(args->out_numargs == 0);
		ret = args->out_args[args->out_numargs - 1].size;
	}
	fuse_put_request(req);

	return ret;
}
```

`struct fuse_req`是`FUSE`请求结构体，其中包括`input`和`output`参数，如下：

```c
// file: fs/fuse/fuse_i.h
struct fuse_req {
	...
	// 请求输入参数
	struct {
		struct fuse_in_header h;
	} in;
	// 请求输出参数
	struct {
		struct fuse_out_header h;
	} out;
	// 请求挂载点
	struct fuse_mount *fm;
};
```

`struct fuse_in_header`是`FUSE`请求输入参数结构体，定义如下：

```c
// file: fs/fuse/fuse_i.h
struct fuse_in_header {
	uint32_t	len;
	uint32_t	opcode;
	uint64_t	unique;
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint32_t	padding;
};
```

`struct fuse_out_header`是`FUSE`请求输出参数结构体，定义如下：

```c
// file: fs/fuse/fuse_i.h
struct fuse_out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};
```

* 兼容性设置

`fuse_adjust_compat`函数用于调整请求的兼容性，根据连接上下文的版本设置请求参数，如下：

```c
// file: fs/fuse/dev.c
static void fuse_adjust_compat(struct fuse_conn *fc, struct fuse_args *args)
{
	// FUSE_STATFS兼容性
	if (fc->minor < 4 && args->opcode == FUSE_STATFS)
		args->out_args[0].size = FUSE_COMPAT_STATFS_SIZE;
	// 版本<9兼容性设置
	if (fc->minor < 9) {
		switch (args->opcode) {
		case FUSE_LOOKUP:
		case FUSE_CREATE:
		case FUSE_MKNOD:
		case FUSE_MKDIR:
		case FUSE_SYMLINK:
		case FUSE_LINK:
			args->out_args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
			break;
		case FUSE_GETATTR:
		case FUSE_SETATTR:
			args->out_args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
			break;
		}
	}
	// 版本<12兼容性设置
	if (fc->minor < 12) {
		switch (args->opcode) {
		case FUSE_CREATE:
			args->in_args[0].size = sizeof(struct fuse_open_in);
			break;
		case FUSE_MKNOD:
			args->in_args[0].size = FUSE_COMPAT_MKNOD_IN_SIZE;
			break;
		}
	}
}
```

* 将参数转换为FUSE请求

`fuse_args_to_req`函数用于将`FUSE`请求参数转换为`FUSE`请求，如下：

```c
// file: fs/fuse/dev.c
static void fuse_args_to_req(struct fuse_req *req, struct fuse_args *args)
{
	// 设置FUSE请求操作码和节点ID
	req->in.h.opcode = args->opcode;
	req->in.h.nodeid = args->nodeid;
	// 设置FUSE请求输入参数
	req->args = args;
	if (args->is_ext)
		req->in.h.total_extlen = args->in_args[args->ext_idx].size / 8;
	if (args->end)
		__set_bit(FR_ASYNC, &req->flags);
}
```

#### 3.3.3 内核空间发送`FUSE`请求

`__fuse_request_send`函数用于发送FUSE请求，如下：

```c
// file: fs/fuse/dev.c
static void fuse_send_one(struct fuse_iqueue *fiq, struct fuse_req *req)
{
	req->in.h.len = sizeof(struct fuse_in_header) +
		fuse_len_args(req->args->in_numargs,
			      (struct fuse_arg *) req->args->in_args);
	fiq->ops->send_req(fiq, req);
}
```

`fuse_len_args`函数用于计算`FUSE`请求输入参数的长度，如下：

```c
// file: fs/fuse/dev.c
unsigned int fuse_len_args(unsigned int numargs, struct fuse_arg *args)
{
	unsigned nbytes = 0;
	unsigned i;
	// 计算FUSE请求输入参数的长度
	for (i = 0; i < numargs; i++)
		nbytes += args[i].size;
	return nbytes;
}
```

在计算`FUSE`请求输入参数的长度后，通过`.send_req`接口发送`FUSE`请求。`ops`在`fuse_get_tree`中设置的，设置为`fuse_dev_fiq_ops`，如下：

```c
// file: fs/fuse/inode.c
static int fuse_get_tree(struct fs_context *fsc)
{
	...
	// 初始化FUSE连接
	fuse_conn_init(fc, fm, fsc->user_ns, &fuse_dev_fiq_ops, NULL);
	...
}
```

`fuse_dev_fiq_ops`是`FUSE`设备队列操作接口，定义如下：

```c
// file: fs/fuse/dev.c
const struct fuse_iqueue_ops fuse_dev_fiq_ops = {
	.send_forget	= fuse_dev_queue_forget,
	.send_interrupt	= fuse_dev_queue_interrupt,
	.send_req	= fuse_dev_queue_req,
};
```

`.send_req`接口设置为`fuse_dev_queue_req`，其实现如下：


```c
// file: fs/fuse/dev.c
static void fuse_dev_queue_req(struct fuse_iqueue *fiq, struct fuse_req *req)
{
	spin_lock(&fiq->lock);
	if (fiq->connected) {
		fuse_request_assign_unique_locked(fiq, req);
		list_add_tail(&req->list, &fiq->pending);
		fuse_dev_wake_and_unlock(fiq);
	} else {
		spin_unlock(&fiq->lock);
		req->out.h.error = -ENOTCONN;
		clear_bit(FR_PENDING, &req->flags);
		fuse_request_end(req);
	}
}
```

在`fiq`处于连接状态时，获取`FUSE`请求的唯一ID，将请求添加到`pending`队列中，并唤醒`FUSE`设备队列线程。

`fuse_request_assign_unique_locked`函数用于为`FUSE`请求分配唯一ID，如下：

```c
// file: fs/fuse/dev.c
static inline void fuse_request_assign_unique_locked(struct fuse_iqueue *fiq,
						     struct fuse_req *req)
{
	if (req->in.h.opcode != FUSE_NOTIFY_REPLY)
		req->in.h.unique = fuse_get_unique_locked(fiq);

	/* tracepoint captures in.h.unique and in.h.len */
	trace_fuse_request_send(req);
}
static u64 fuse_get_unique_locked(struct fuse_iqueue *fiq)
{	
	// 增加请求计数器
	fiq->reqctr += FUSE_REQ_ID_STEP;
	return fiq->reqctr;
}
```

#### 3.3.4 用户空间获取`FUSE`请求

上面几个阶段是内核空间处理的工作，现在让我们回到用户空间，看看用户空间是如何获取`FUSE`请求的。让我们回到用户空间，用户在挂载fuse文件系统后，通过`fuse_session_loop`或`fuse_session_loop_mt`函数进入事件循环，等待`FUSE`请求的到来。如下：

```c
// file: libfuse/example/hello_ll.c
int main(int argc, char *argv[])
{
	...
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else {
		config = fuse_loop_cfg_create();
		fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
		fuse_loop_cfg_set_max_threads(config, opts.max_threads);
		ret = fuse_session_loop_mt(se, config);
		fuse_loop_cfg_destroy(config);
		config = NULL;
	}
	...
}
```

我们以`fuse_session_loop`函数为例，说明用户空间是如何获取`FUSE`请求的。其实现如下：

```c
// file: ibfuse/lib/fuse_loop.c
int fuse_session_loop(struct fuse_session *se)
{
	int res = 0;
	struct fuse_buf fbuf = {
		.mem = NULL,
	};
	while (!fuse_session_exited(se)) {
		// 接收FUSE请求
		res = fuse_session_receive_buf_internal(se, &fbuf, NULL);
		if (res == -EINTR) continue;
		if (res <= 0) break;
		// 处理FUSE请求
		fuse_session_process_buf(se, &fbuf);
	}
	// 释放FUSE请求缓冲区
	fuse_buf_free(&fbuf);
	if(res > 0) res = 0;
	if(se->error != 0) res = se->error;
	if (se->uring.pool) fuse_uring_stop(se);
	return res;
}
```

`fuse_session_receive_buf_internal`函数是对`_fuse_session_receive_buf`函数的封装，用于接收`FUSE`请求。如下：

```c
file: libfuse/lib/fuse_lowlevel.c
int fuse_session_receive_buf_internal(struct fuse_session *se,
				      struct fuse_buf *buf,
				      struct fuse_chan *ch)
{
	if (unlikely(!se->got_init) && !se->buf_reallocable)
		se->buf_reallocable = true;
	return _fuse_session_receive_buf(se, buf, ch, true);
}
```

`_fuse_session_receive_buf`函数通过`SPLICE`或`read`系统调用接收`FUSE`请求。我们这里只分析最简单的情况，即通过`read`获取`FUSE`请求。如下：

```c
static int _fuse_session_receive_buf(struct fuse_session *se,
				     struct fuse_buf *buf, struct fuse_chan *ch,
				     bool internal)
{
	...
restart:
	if (se->io != NULL) {
		// 通过io接口读取FUSE请求
		res = se->io->read(ch ? ch->fd : se->fd, buf->mem, bufsize,
				   se->userdata);
	} else {
		// 通过read系统调用读取FUSE请求
		res = read(ch ? ch->fd : se->fd, buf->mem, bufsize);
	}
	err = errno;
	trace_request_receive(err);
	...
}
```

示例中我们没有设置`ch`和`se->io`，通过`se->fd`读取`FUSE`请求，`se->fd`是通过打开`/dev/fuse`设备文件获得的。其对应的读取接口设置为`fuse_dev_read`，如下：

```c
// file: fs/fuse/dev.c
const struct file_operations fuse_dev_operations = {
	...
	.read_iter	= fuse_dev_read,
	...
};
```

其实现如下：

```c
// file: fs/fuse/dev.c
static ssize_t fuse_dev_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_copy_state cs;
	struct file *file = iocb->ki_filp;
	// 获取FUSE设备结构体
	struct fuse_dev *fud = fuse_get_dev(file);

	if (IS_ERR(fud)) return PTR_ERR(fud);
	if (!user_backed_iter(to)) return -EINVAL;
	// 设置FUSE复制状态
	fuse_copy_init(&cs, true, to);
	// 执行FUSE设备读取操作
	return fuse_dev_do_read(fud, file, &cs, iov_iter_count(to));
}
```

`fuse_dev_do_read`函数用于读取一个`FUSE`请求到用户空间，如下:

```c
// file: fs/fuse/dev.c
static ssize_t fuse_dev_do_read(struct fuse_dev *fud, struct file *file,
				struct fuse_copy_state *cs, size_t nbytes)
{
	ssize_t err;
	struct fuse_conn *fc = fud->fc;
	struct fuse_iqueue *fiq = &fc->iq;
	struct fuse_pqueue *fpq = &fud->pq;
	...

 restart:
	for (;;) {
		spin_lock(&fiq->lock);
		// 检查FUSE请求队列是否有请求
		if (!fiq->connected || request_pending(fiq)) break;
		spin_unlock(&fiq->lock);

		// 等待FUSE请求队列有请求
		if (file->f_flags & O_NONBLOCK) return -EAGAIN;
		err = wait_event_interruptible_exclusive(fiq->waitq,
				!fiq->connected || request_pending(fiq));
		if (err) return err;
	}
	// 检查FUSE请求队列是否已断开
	if (!fiq->connected) {
		err = fc->aborted ? -ECONNABORTED : -ENODEV;
		goto err_unlock;
	}
	if (!list_empty(&fiq->interrupts)) {
		req = list_entry(fiq->interrupts.next, struct fuse_req, intr_entry);
		// 处理FUSE中断请求
		return fuse_read_interrupt(fiq, cs, nbytes, req);
	}
	if (forget_pending(fiq)) {
		// 处理FUSE忘记请求
		if (list_empty(&fiq->pending) || fiq->forget_batch-- > 0)
			return fuse_read_forget(fc, fiq, cs, nbytes);
		if (fiq->forget_batch <= -8) fiq->forget_batch = 16;
	}

	// 获取FUSE请求队列中的第一个请求
	req = list_entry(fiq->pending.next, struct fuse_req, list);
	clear_bit(FR_PENDING, &req->flags);
	list_del_init(&req->list);
	spin_unlock(&fiq->lock);

	// 获取请求参数和请求大小
	args = req->args;
	reqsize = req->in.h.len;

	// 处理FUSE用户空间不足的情况
	if (nbytes < reqsize) {
		req->out.h.error = -EIO;
		if (args->opcode == FUSE_SETXATTR)
			req->out.h.error = -E2BIG;
		fuse_request_end(req);
		goto restart;
	}
	spin_lock(&fpq->lock);

	// 检查FUSE连接是否已断开
	if (!fpq->connected) {
		req->out.h.error = err = -ECONNABORTED;
		goto out_end;

	}
	list_add(&req->list, &fpq->io);
	spin_unlock(&fpq->lock);
	cs->req = req;
	// 复制FUSE请求头到用户空间
	err = fuse_copy_one(cs, &req->in.h, sizeof(req->in.h));
	if (!err)
		// 复制FUSE请求参数到用户空间
		err = fuse_copy_args(cs, args->in_numargs, args->in_pages,
				     (struct fuse_arg *) args->in_args, 0);
	fuse_copy_finish(cs);
	spin_lock(&fpq->lock);
	clear_bit(FR_LOCKED, &req->flags);
	if (!fpq->connected) {
		err = fc->aborted ? -ECONNABORTED : -ENODEV;
		goto out_end;
	}
	if (err) {
		req->out.h.error = -EIO;
		goto out_end;
	}
	if (!test_bit(FR_ISREPLY, &req->flags)) {
		err = reqsize;
		goto out_end;
	}
	// 将请求添加到处理队列
	hash = fuse_req_hash(req->in.h.unique);
	list_move_tail(&req->list, &fpq->processing[hash]);
	__fuse_get_request(req);
	set_bit(FR_SENT, &req->flags);
	spin_unlock(&fpq->lock);
	smp_mb__after_atomic();
	if (test_bit(FR_INTERRUPTED, &req->flags))
		queue_interrupt(req);
	fuse_put_request(req);

	return reqsize;
	...
}
```

#### 3.3.5 用户空间处理`FUSE`请求

用户空间获取到`FUSE`请求后，通过`fuse_session_process_buf`函数处理`FUSE`请求， 改函数是对`fuse_session_process_buf_internal`函数的封装，如下：

```c
file: libfuse/lib/fuse_lowlevel.c
void fuse_session_process_buf(struct fuse_session *se,
			      const struct fuse_buf *buf)
{
	fuse_session_process_buf_internal(se, buf, NULL);
}
void fuse_session_process_buf_internal(struct fuse_session *se,
				  const struct fuse_buf *buf, struct fuse_chan *ch)
{
	const size_t write_header_size = sizeof(struct fuse_in_header) +
		sizeof(struct fuse_write_in);
	struct fuse_bufvec bufv = { .buf[0] = *buf, .count = 1 };
	struct fuse_bufvec tmpbuf = FUSE_BUFVEC_INIT(write_header_size);
	struct fuse_in_header *in;
	...

	// 分配FUSE请求结构体
	req = fuse_ll_alloc_req(se);
	if (req == NULL) {
		// 分配FUSE请求结构体失败，发送错误响应
		struct fuse_out_header out = {
			.unique = in->unique,
			.error = -ENOMEM,
		};
		struct iovec iov = {
			.iov_base = &out,
			.iov_len = sizeof(struct fuse_out_header),
		};
		fuse_send_msg(se, ch, &iov, 1, NULL);
		goto clear_pipe;
	}
	// 设置FUSE请求结构体参数, 包括:unique, uid, gid, pid
	fuse_session_in2req(req, in);
	req->ch = ch ? fuse_chan_get(ch) : NULL;
	// 检查FUSE请求操作码是否合法
	err = fuse_req_opcode_sanity_ok(se, in->opcode);
	if (err) goto reply_err;
	// 检查FUSE请求是否允许根用户操作
	err = fuse_req_check_allow_root(se, in->opcode, in->uid);
	if (err) goto reply_err;

	...
	err = ENOSYS;
	// 检查FUSE请求操作码是否超出范围或未实现
	if (in->opcode >= FUSE_MAXOP || !fuse_ll_ops[in->opcode].func)
		goto reply_err;
	...
	// 获取FUSE请求参数
	inarg = (void *) &in[1];
	if (in->opcode == FUSE_WRITE && se->op.write_buf)
		// 处理FUSE写请求
		do_write_buf(req, in->nodeid, inarg, buf);
	else if (in->opcode == FUSE_NOTIFY_REPLY)
		// 处理FUSE通知回复请求
		do_notify_reply(req, in->nodeid, inarg, buf);
	else
		// 处理其他FUSE请求操作
		fuse_ll_ops[in->opcode].func(req, in->nodeid, inarg);

out_free:
	free(mbuf);
	return;
}
```

`fuse_ll_ops`是`FUSE`请求操作函数数组，每个操作码对应不同的操作，其定义如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static struct {
	void (*func)(fuse_req_t req, const fuse_ino_t node, const void *arg);
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { do_lookup,      "LOOKUP"	     },
	...
}
```

#### 3.3.6 用户空间处理`FUSE_INIT`请求

我们目前分析`FUSE_INIT`请求，其对应的处理函数为`do_init`，如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static struct {
	void (*func)(fuse_req_t req, const fuse_ino_t node, const void *arg);
	const char *name;
} fuse_ll_ops[] = {
	...
	[FUSE_INIT]	   = { do_init,	       "INIT"	     },
	...
}
```

`do_init`函数是对`_do_init`函数的封装，后者进行具体的`init`操作，如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static __attribute__((no_sanitize("thread"))) void
do_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	_do_init(req, nodeid, inarg, NULL);
}
static __attribute__((no_sanitize("thread"))) void
_do_init(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
	 const void *in_payload)
{
	// init请求参数的结构体
	const struct fuse_init_in *arg = op_in;
	// init响应参数的结构体
	struct fuse_init_out outarg;
	struct fuse_session *se = req->se;
	size_t bufsize = se->bufsize;
	// init响应参数的大小
	size_t outargsize = sizeof(outarg);
	
	...
	se->conn.proto_major = arg->major;
	se->conn.proto_minor = arg->minor;
	se->conn.capable_ext = 0;
	se->conn.want_ext = 0;

	// 初始化init响应参数
	memset(&outarg, 0, sizeof(outarg));
	outarg.major = FUSE_KERNEL_VERSION;
	outarg.minor = FUSE_KERNEL_MINOR_VERSION;

	if (arg->major < 7) {
		fuse_log(FUSE_LOG_ERR, "fuse: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		// 不支持低于7.0的协议版本，返回EPROTO错误
		fuse_reply_err(req, EPROTO);
		return;
	}

	if (arg->major > 7) {
		// 7.X版本需要等待后续INIT请求
		send_reply_ok(req, &outarg, sizeof(outarg));
		return;
	}
	
	...
	se->conn.time_gran = 1;
	if (se->op.init) {
		se->conn.capable = fuse_lower_32_bits(se->conn.capable_ext);
		// 调用用户空间init函数
		se->op.init(se->userdata, &se->conn);
		// 必要时转化`wanted`标记
		fuse_convert_to_conn_want_ext(&se->conn);
	}

	...
	// 检查并设置应答参数
	...
	outarg.flags = outargflags;

	se->got_init = 1;
	send_reply_ok(req, &outarg, outargsize);
	if (enable_io_uring)
		fuse_uring_wake_ring_threads(se);
}
```

在`_do_init`函数中, `.init`为用户空间的扩展初始化函数，用于初始化`FUSE`文件系统的连接参数，设置为`hello_ll_init`。如下：

```c
// file: libfuse/example/hello_ll.c
static const struct fuse_lowlevel_ops hello_ll_oper = {
	.init = hello_ll_init,
	...
};
```

其实现如下：

```c
// file: libfuse/example/hello_ll.c
static void hello_ll_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;
	conn->no_interrupt = 1;
	conn->want = FUSE_CAP_ASYNC_READ;
	conn->want &= ~FUSE_CAP_ASYNC_READ;
}
```

我们略过具体的初始化检查过程，只关注处理正常和错误的情况，处理正常时通过`send_reply_ok`函数发送`init`响应；异常时通过`fuse_reply_err`发送错误情况，如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static int send_reply_ok(fuse_req_t req, const void *arg, size_t argsize)
{
	return send_reply(req, 0, arg, argsize);
}
int fuse_reply_err(fuse_req_t req, int err)
{
	return send_reply(req, -err, NULL, 0);
}
```

#### 3.3.7 用户空间处理返回处理结果

`send_reply_ok`和`fuse_reply_err`函数都是通过`send_reply`函数实现的，后者根据错误码和参数大小发送响应, 最终调用`fuse_send_msg`发送响应。其实现如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static int send_reply(fuse_req_t req, int error, const void *arg, size_t argsize)
{
	if (req->flags.is_uring)
		return send_reply_uring(req, error, arg, argsize);

	struct iovec iov[2];
	int count = 1;
	if (argsize) {
		iov[1].iov_base = (void *) arg;
		iov[1].iov_len = argsize;
		count++;
	}
	return send_reply_iov(req, error, iov, count);
}
static int send_reply_iov(fuse_req_t req, int error, struct iovec *iov,
			  int count)
{
	int res;
	// 发送响应并释放请求
	res = fuse_send_reply_iov_nofree(req, error, iov, count);
	fuse_free_req(req);
	return res;
}
int fuse_send_reply_iov_nofree(fuse_req_t req, int error, struct iovec *iov,
			       int count)
{
	struct fuse_out_header out;
	...
	// 初始化响应头
	out.unique = req->unique;
	out.error = error;
	// 设置响应头的大小
	iov[0].iov_base = &out;
	iov[0].iov_len = sizeof(struct fuse_out_header);
	// 发送响应消息
	return fuse_send_msg(req->se, req->ch, iov, count, req);
}
```

`fuse_send_msg`函数通过`io_uring`或者`writev`方式发送响应消息，如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static int fuse_send_msg(struct fuse_session *se, struct fuse_chan *ch,
			 struct iovec *iov, int count, fuse_req_t req)
{
	// 获取响应头指针
	struct fuse_out_header *out = iov[0].iov_base;
	bool is_uring = req && req->flags.is_uring ? true : false;

	// 计算响应消息的总大小
	out->len = iov_length(iov, count);
	...
	if (is_uring)
		err = fuse_send_msg_uring(req, iov, count);
	else
		err = fuse_write_msg_dev(se, ch, iov, count);

	trace_request_reply(out->unique, out->len, out->error, err);
	return err;
}
```

`fuse_write_msg_dev`通过`writev`系统调用发送响应消息，如下：

```c
//file: libfuse/lib/fuse_lowlevel.c
static int fuse_write_msg_dev(struct fuse_session *se, struct fuse_chan *ch,
			     struct iovec *iov, int count)
{
	ssize_t res;
	int err;

	if (se->io != NULL)
		res = se->io->writev(ch ? ch->fd : se->fd, iov, count, se->userdata);
	else	
		// 使用默认的writev系统调用发送响应消息
		res = writev(ch ? ch->fd : se->fd, iov, count);

	if (res == -1) { ... }
	return 0;
}
```

我们继续分析通过`writev`发送响应消息的情况，`/dev/fuse`设备文件设置的`.write_iter`接口为`fuse_dev_write`，如下：

```c
// file: fs/fuse/dev.c
static ssize_t fuse_dev_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_copy_state cs;
	// 获取fuse_dev结构体指针
	struct fuse_dev *fud = __fuse_get_dev(iocb->ki_filp);

	if (!fud) return -EPERM;
	if (!user_backed_iter(from)) return -EINVAL;
	// 设置负责状态
	fuse_copy_init(&cs, false, from);
	// 执行写操作
	return fuse_dev_do_write(fud, &cs, iov_iter_count(from));
}
```

`fuse_dev_do_write`函数将用户空间处理后的应答写入到请求中，其实现如下：

```c
// file: fs/fuse/dev.c
static ssize_t fuse_dev_do_write(struct fuse_dev *fud,
				 struct fuse_copy_state *cs, size_t nbytes)
{
	int err;
	struct fuse_conn *fc = fud->fc;
	struct fuse_pqueue *fpq = &fud->pq;
	struct fuse_req *req;
	struct fuse_out_header oh;

	err = -EINVAL;
	// 检查请求大小是否足够
	if (nbytes < sizeof(struct fuse_out_header)) goto out;
	// 复制响应头
	err = fuse_copy_one(cs, &oh, sizeof(oh));
	if (err) goto copy_finish;
	// 检查响应头的大小是否与请求大小一致
	err = -EINVAL;
	if (oh.len != nbytes) goto copy_finish;

	// `oh.unique`为0表示无请求ID，为通知消息
	if (!oh.unique) {
		err = fuse_notify(fc, oh.error, nbytes - sizeof(oh), cs);
		goto copy_finish;
	}
	// 检查错误码是否有效
	err = -EINVAL;
	if (oh.error <= -512 || oh.error > 0)
		goto copy_finish;

	spin_lock(&fpq->lock);
	req = NULL;
	if (fpq->connected)
		// 查找请求，通过`unique`从处理消息队列中查找请求
		req = fuse_request_find(fpq, oh.unique & ~FUSE_INT_REQ_BIT);
	...

	clear_bit(FR_SENT, &req->flags);
	// 将请求移动到处理队列中
	list_move(&req->list, &fpq->io);
	// 设置请求的响应头
	req->out.h = oh;
	set_bit(FR_LOCKED, &req->flags);
	spin_unlock(&fpq->lock);
	cs->req = req;
	if (!req->args->page_replace)
		cs->move_folios = false;

	if (oh.error)
		// 检测并设置错误码
		err = nbytes != sizeof(oh) ? -EINVAL : 0;
	else	
		// 复制响应参数
		err = fuse_copy_out_args(cs, req->args, nbytes);
	fuse_copy_finish(cs);

	spin_lock(&fpq->lock);
	clear_bit(FR_LOCKED, &req->flags);
	// 检查连接状态和错误码
	if (!fpq->connected) err = -ENOENT;
	else if (err) req->out.h.error = -EIO;
	// 如果不是私有请求，将请求从处理队列中移除
	if (!test_bit(FR_PRIVATE, &req->flags))
		list_del_init(&req->list);
	spin_unlock(&fpq->lock);
	// 结束请求处理
	fuse_request_end(req);
out:
	return err ? err : nbytes;
copy_finish:
	fuse_copy_finish(cs);
	goto out;
}
```

`fuse_request_find`函数通过`unique`从处理消息队列中查找请求，如下：

```c
// file: fs/fuse/dev.c
struct fuse_req *fuse_request_find(struct fuse_pqueue *fpq, u64 unique)
{
	unsigned int hash = fuse_req_hash(unique);
	struct fuse_req *req;
	// 遍历处理消息队列，查找匹配的请求
	list_for_each_entry(req, &fpq->processing[hash], list) {
		if (req->in.h.unique == unique)
			return req;
	}
	return NULL;
}
```

#### 3.3.8 内核空间处理返回结果

用户空间在写入处理结果后，调用`fuse_request_end`函数继续后续的处理。实现如下：

```c
// file: fs/fuse/dev.c
void fuse_request_end(struct fuse_req *req)
{
	struct fuse_mount *fm = req->fm;
	struct fuse_conn *fc = fm->fc;
	struct fuse_iqueue *fiq = &fc->iq;
	// 检查请求是否已完成
	if (test_and_set_bit(FR_FINISHED, &req->flags))
		goto put_request;

	trace_fuse_request_end(req);
	// 检查请求是否被中断
	if (test_bit(FR_INTERRUPTED, &req->flags)) {
		spin_lock(&fiq->lock);
		list_del_init(&req->intr_entry);
		spin_unlock(&fiq->lock);
	}
	WARN_ON(test_bit(FR_PENDING, &req->flags));
	WARN_ON(test_bit(FR_SENT, &req->flags));
	if (test_bit(FR_BACKGROUND, &req->flags)) {
		// 处理后台请求
		spin_lock(&fc->bg_lock);
		clear_bit(FR_BACKGROUND, &req->flags);
		if (fc->num_background == fc->max_background) {
			fc->blocked = 0;
			wake_up(&fc->blocked_waitq);
		} else if (!fc->blocked) {
			if (waitqueue_active(&fc->blocked_waitq))
				wake_up(&fc->blocked_waitq);
		}
		// 更新后台请求统计信息
		fc->num_background--;
		fc->active_background--;
		flush_bg_queue(fc);
		spin_unlock(&fc->bg_lock);
	} else {
		// 唤醒等待请求,和`request_wait_answer`匹配
		wake_up(&req->waitq);
	}
	// 异步请求，调用结束回调函数
	if (test_bit(FR_ASYNC, &req->flags))
		req->args->end(fm, req->args, req->out.h.error);
put_request:
	fuse_put_request(req);
}
```

`fuse_request_end`函数在唤醒等待请求后，继续返回内核空间，处理后续的请求，此时我们返回`request_wait_answer`继续后续处理，

```c
// file: fs/fuse/dev.c
ssize_t __fuse_simple_request(struct mnt_idmap *idmap,
			      struct fuse_mount *fm,
			      struct fuse_args *args)
{
	...
	__fuse_request_send(req);
	// 请求完成，设置返回值
	ret = req->out.h.error;
	if (!ret && args->out_argvar) {
		BUG_ON(args->out_numargs == 0);
		ret = args->out_args[args->out_numargs - 1].size;
	}
	// 释放请求
	fuse_put_request(req);
	return ret;
}
```

以`fuse_send_init`为例，在请求完成后继续后续处理，如下：

```c
// file: fs/fuse/inode.c
int fuse_send_init(struct fuse_mount *fm)
{
	// 创建FUSE_INIT请求参数
	struct fuse_init_args *ia = fuse_new_init(fm);
	int err;

	if (fm->fc->sync_init) {
		// 同步发送FUSE_INIT请求
		err = fuse_simple_request(fm, &ia->args);
		if (err > 0) err = 0;
	} else {
		// 异步发送FUSE_INIT请求
		ia->args.end = process_init_reply;
		err = fuse_simple_background(fm, &ia->args, GFP_KERNEL);
		if (!err) return 0;
	}
	// 处理FUSE_INIT回复
	process_init_reply(fm, &ia->args, err);
	if (fm->fc->conn_error) return -ENOTCONN;
	return 0;
}
```

此时调用`process_init_reply`处理FUSE_INIT回复，如下：

```c
// file: fs/fuse/inode.c
static void process_init_reply(struct fuse_mount *fm, struct fuse_args *args,
			       int error)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_init_args *ia = container_of(args, typeof(*ia), args);
	struct fuse_init_out *arg = &ia->out;
	bool ok = true;

	// 检查错误码和协议版本
	if (error || arg->major != FUSE_KERNEL_VERSION)
		ok = false;
	else { 
		... 
		// 正常处理FUSE_INIT回复
	}
	kfree(ia);

	if (!ok) {
		fc->conn_init = 0;
		fc->conn_error = 1;
	}
	// 设置连接为已初始化状态
	fuse_set_initialized(fc);
	// 唤醒所有等待连接初始化的进程
	wake_up_all(&fc->blocked_waitq);
}
```

经过以上处理，FUSE_INIT回复被正常处理，连接状态被设置为已初始化，等待连接初始化的进程被唤醒。

### 3.4 `open`的实现过程

#### 3.4.1 内核空间发送`open`请求

我们以打开文件为例，`fuse`文件对应的`open`接口为`fuse_open`，如下：

```c
// file: fs/fuse/file.c
static const struct file_operations fuse_file_operations = {
	...
	.open		= fuse_open,
	...
};
```

其实现如下：

```c
// file: fs/fuse/file.c
static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = fm->fc;
	struct fuse_file *ff;
	...

	// 调用通用文件打开函数
	err = generic_file_open(inode, file);
	if (err) return err;
	...
	// 发送FUSE_OPEN请求
	err = fuse_do_open(fm, get_node_id(inode), file, false);
	if (!err) {
		ff = file->private_data;
		err = fuse_finish_open(inode, file);
		if (err)
			fuse_sync_release(fi, ff, file->f_flags);
		else if (is_truncate)
			fuse_truncate_update_attr(inode, file);
	}
	...
	return err;
}
```

`fuse_do_open`函数调用`fuse_file_open`函数发送FUSE_OPEN请求，请求成功后设置文件的`private_data`为`fuse_file`结构体，如下：

```c
// file: fs/fuse/file.c
int fuse_do_open(struct fuse_mount *fm, u64 nodeid, struct file *file,
		 bool isdir)
{
	struct fuse_file *ff = fuse_file_open(fm, nodeid, file->f_flags, isdir);
	// 
	if (!IS_ERR(ff)) file->private_data = ff;
	return PTR_ERR_OR_ZERO(ff);
}
```

`fuse_file_open`函数分配`fuse_file`后，发送FUSE_OPEN请求，请求成功后修改`fuse_file`信息，如下：

```c
// file: fs/fuse/file.c
struct fuse_file *fuse_file_open(struct fuse_mount *fm, u64 nodeid,
				 unsigned int open_flags, bool isdir)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_file *ff;
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;
	bool open = isdir ? !fc->no_opendir : !fc->no_open;
	bool release = !isdir || open;

	// 分配并初始化fuse_file结构体
	ff = fuse_file_alloc(fm, release);
	if (!ff) return ERR_PTR(-ENOMEM);

	ff->fh = 0;
	ff->open_flags = FOPEN_KEEP_CACHE | (isdir ? FOPEN_CACHE_DIR : 0);
	if (open) {
		// 存储FUSE_OPEN回复
		struct fuse_open_out *outargp = &ff->args->open_outarg;
		int err;

		// 发送FUSE_OPEN请求
		err = fuse_send_open(fm, nodeid, open_flags, opcode, outargp);
		if (!err) {
			// 存储FUSE_OPEN回复
			ff->fh = outargp->fh;
			ff->open_flags = outargp->open_flags;
		} else if (err != -ENOSYS) {
			// 处理FUSE_OPEN回复错误(ENOSYS)
			fuse_file_free(ff);
			return ERR_PTR(err);
		} else {
			// 处理FUSE_OPEN回复错误
			if (isdir) {
				kfree(ff->args);
				ff->args = NULL;
				fc->no_opendir = 1;
			} else {
				fc->no_open = 1;
			}
		}
	}

	if (isdir) ff->open_flags &= ~FOPEN_DIRECT_IO;
	// 存储节点ID
	ff->nodeid = nodeid;
	return ff;
}
```

其中核心的部分是发送FUSE_OPEN请求，通过`fuse_send_open`函数实现，如下：

```c
// file: fs/fuse/file.c
static int fuse_send_open(struct fuse_mount *fm, u64 nodeid,
			  unsigned int open_flags, int opcode,
			  struct fuse_open_out *outargp)
{
	struct fuse_open_in inarg;
	FUSE_ARGS(args);

	// 初始化FUSE_OPEN请求参数
	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = open_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fm->fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;

	if (fm->fc->handle_killpriv_v2 &&
	    (inarg.flags & O_TRUNC) && !capable(CAP_FSETID)) {
		inarg.open_flags |= FUSE_OPEN_KILL_SUIDGID;
	}
	// 设置FUSE_OPEN请求参数
	args.opcode = opcode;
	args.nodeid = nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(*outargp);
	args.out_args[0].value = outargp;
	// 发送FUSE_OPEN请求
	return fuse_simple_request(fm, &args);
}
```

#### 3.4.2 用户空间处理`open`请求

打开文件对应的`opcode`为`FUSE_OPEN`，用户空间对于的实现为：

```c
static struct {
	void (*func)(fuse_req_t req, const fuse_ino_t node, const void *arg);
	const char *name;
} fuse_ll_ops[] = {
	...
	[FUSE_OPEN]	   = { do_open,	       "OPEN"	     },
	...
};
```

`do_open`是对`_do_open`的封装，后者实现了FUSE_OPEN请求的处理，如下：

```c
// file: libfuse/lib/fuse_lowlevel.c
static void do_open(fuse_req_t req, const fuse_ino_t nodeid, const void *inarg)
{
	_do_open(req, nodeid, inarg, NULL);
}
static void _do_open(fuse_req_t req, const fuse_ino_t nodeid, const void *op_in,
		     const void *in_payload)
{
	(void)in_payload;
	struct fuse_open_in *arg = (struct fuse_open_in *)op_in;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	// 处理FUSE_OPEN请求
	if (req->se->op.open)
		req->se->op.open(req, nodeid, &fi);
	else if (req->se->conn.want_ext & FUSE_CAP_NO_OPEN_SUPPORT)
		fuse_reply_err(req, ENOSYS);
	else
		fuse_reply_open(req, &fi);
}
```

我们设置了`.open`接口，如下：

```c
// file: libfuse/example/hello_ll.c
static const struct fuse_lowlevel_ops hello_ll_oper = {
	...
	.open = hello_ll_open,
	...
};
```

设置为`hello_ll_open`, 其实现如下：

```c
// file: libfuse/example/hello_ll.c
static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	if (ino != 2)
		fuse_reply_err(req, EISDIR);
	else if ((fi->flags & O_ACCMODE) != O_RDONLY)
		fuse_reply_err(req, EACCES);
	else
		fuse_reply_open(req, fi);
}
```

`fuse_reply_open`函数回复正确打开文件，如下：

```c
// file: libfuse/lib/fuse_lowlevel.c
int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
	struct fuse_open_out arg;
	memset(&arg, 0, sizeof(arg));
	// 填充FUSE_OPEN回复参数
	fill_open(&arg, f);
	return send_reply_ok(req, &arg, sizeof(arg));
}
```

### 3.5 卸载`FUSE`文件系统

#### 3.5.1 用户空间卸载`FUSE`文件系统

用户空间通过`fuse_session_unmount`函数卸载`FUSE`文件系统，该函数通过调用`fuse_kern_unmount`函数，进而调用`umount2`卸载文件系统。 如下：

```c
// file: libfuse/lib/fuse_lowlevel.c
void fuse_session_unmount(struct fuse_session *se)
{
	if (se->mountpoint != NULL) {
		char *mountpoint = atomic_exchange(&se->mountpoint, NULL);

		fuse_kern_unmount(mountpoint, se->fd);
		se->fd = -1;
		free(mountpoint);
	}
}
// file: libfuse/lib/mount.c
void fuse_kern_unmount(const char *mountpoint, int fd)
{
	int res;
	if (fd != -1) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = 0;
		res = poll(&pfd, 1, 0);
		// 关闭文件描述符
		close(fd);

		if (res == 1 && (pfd.revents & POLLERR))
			return;
	}

	if (geteuid() == 0) {
		fuse_mnt_umount("fuse", mountpoint, mountpoint,  1);
		return;
	}
	// 调用umount2卸载文件系统
	res = umount2(mountpoint, 2);
	if (res == 0)
		return;
	// 如果umount2失败，使用`fusermount3`卸载文件系统
	char const * const argv[] =
		{ FUSERMOUNT_PROG, "--unmount", "--quiet", "--lazy",
				"--", mountpoint, NULL };
	int status = fusermount_posix_spawn(NULL, argv, NULL);
	if(status != 0) {
		fuse_log(FUSE_LOG_ERR, "Spawning %s to unmount failed: %s",
			 FUSERMOUNT_PROG, strerror(-status));
		return;
	}
}
```

#### 3.5.2 `umount2`系统调用

`umount2`系统调用对应内核空间的`umount`函数，如下：

```c
// file: fs/namespace.c
SYSCALL_DEFINE2(umount, char __user *, name, int, flags)
{
	return ksys_umount(name, flags);
}
```

`ksys_umount`函数查找挂载路径后调用`path_umount`函数卸载文件系统。整体的调用路径如下：

```c
// file: fs/namespace.c
static int ksys_umount(char __user *name, int flags)
{
	...
	ret = user_path_at(AT_FDCWD, name, lookup_flags, &path);
	return path_umount(&path, flags);
		--> mntput_no_expire(mnt);
			--> mntput_no_expire_slowpath(mnt);
				--> cleanup_mnt(mnt);
					--> deactivate_super(mnt->mnt.mnt_sb);
						--> deactivate_locked_super(s);
}
```

`deactivate_locked_super`函数用于停用超级块，如下：

```c
// file: fs/super.c
void deactivate_locked_super(struct super_block *s)
{
	struct file_system_type *fs = s->s_type;
	if (atomic_dec_and_test(&s->s_active)) {
		shrinker_free(s->s_shrink);
		// 调用文件系统的kill_sb函数停用超级块
		fs->kill_sb(s);

		kill_super_notify(s);

		list_lru_destroy(&s->s_dentry_lru);
		list_lru_destroy(&s->s_inode_lru);

		put_filesystem(fs);
		put_super(s);
	} else {
		super_unlock_excl(s);
	}
}
```

`FUSE`文件系统的`.kill_sb`实现为`fuse_kill_sb_anon`，如下：

```c
// file: fs/fuse/inode.c
static void fuse_kill_sb_anon(struct super_block *sb)
{
	fuse_sb_destroy(sb);
	kill_anon_super(sb);
	fuse_mount_destroy(get_fuse_mount_super(sb));
}
```

# 4 总结

通过本文，我们以`hello_ll`示例分析了`FUSE`文件系统的基本原理和实现。我们详细介绍了`FUSE`文件系统的内核空间和用户空间的交互过程、工作原理，通过本文的分析，我们可以更好地理解`FUSE`文件系统的工作原理和实现机制。

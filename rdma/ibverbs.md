# RDMA verbs的内核实现

## 1 简介

RDMA（Remote Direct Memory Access）是一种允许计算机直接访问远程内存的技术，极大地提高了数据传输的效率。RDMA verbs是RDMA技术的核心接口，使用户程序能够利用RDMA功能进行高效的数据传输。

## 2 用户程序

我们使用libibverbs提供的示例程序`rc_pingpong.c`来演示RDMA verbs的使用。核心的代码如下：

```c
int main(int argc, char *argv[])
{
	struct ibv_device      **dev_list;
	struct ibv_device	*ib_dev;
	struct pingpong_context *ctx;
	struct pingpong_dest     my_dest;
	struct pingpong_dest    *rem_dest;
        ...
        // 获取系统页面大小
	page_size = sysconf(_SC_PAGESIZE);

        // 获取IB设备列表
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) { ... }

        // 如果未指定IB设备，默认使用第一个设备
	if (!ib_devname) {
		ib_dev = *dev_list;
		if (!ib_dev) { ... }
	} else {
                // 遍历设备列表，查找指定的IB设备
		int i;
		for (i = 0; dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
				break;
		ib_dev = dev_list[i];
		if (!ib_dev) { ... }
	}

        // 初始化RDMA上下文
	ctx = pp_init_ctx(ib_dev, size, rx_depth, ib_port, use_event);
	if (!ctx) return 1;
        // 提交接收队列
	routs = pp_post_recv(ctx, ctx->rx_depth);
	if (routs < ctx->rx_depth) { ... }

        // 获取端口信息
	if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) { ... }
        
        // 设置并检查本地LID
	my_dest.lid = ctx->portinfo.lid;
	if (ctx->portinfo.link_layer != IBV_LINK_LAYER_ETHERNET && !my_dest.lid) { ... }

        // 设置并检查GID索引
	if (gidx >= 0) {
                // 查询GID索引
		if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) { ... }
	} else
		memset(&my_dest.gid, 0, sizeof my_dest.gid);

        // 设置并检查QPN和PSN
	my_dest.qpn = ctx->qp->qp_num;
	my_dest.psn = lrand48() & 0xffffff;
	inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);

        // 客户端与服务端交换目标地址
	if (servername)
		rem_dest = pp_client_exch_dest(servername, port, &my_dest);
	else
		rem_dest = pp_server_exch_dest(ctx, ib_port, mtu, port, sl, &my_dest, gidx);

	if (!rem_dest) return 1;

	inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid);

        // 客户端与服务端建立连接
	if (servername)
		if (pp_connect_ctx(ctx, ib_port, my_dest.psn, mtu, sl, rem_dest, gidx))
			return 1;

	ctx->pending = PINGPONG_RECV_WRID;

	if (servername) {
                ... 
                // 客户端发送数据
		if (pp_post_send(ctx)) { ... }
		ctx->pending |= PINGPONG_SEND_WRID;
	}

        // 获取开始时间
	if (gettimeofday(&start, NULL)) { ... }

	rcnt = scnt = 0;
	while (rcnt < iters || scnt < iters) {
		int ret;

		if (use_ts) {
                        ...
		} else {
			int ne, i;
			struct ibv_wc wc[2];

			do {
                                // 轮询完成队列（Completion Queue）
				ne = ibv_poll_cq(pp_cq(ctx), 2, wc);
				if (ne < 0) { ... }
			} while (!use_event && ne < 1);

			for (i = 0; i < ne; ++i) {
                                // 解析完成队列中的完成记录（Completion Record）
				ret = parse_single_wc(ctx, &scnt, &rcnt, &routs,
						      iters, wc[i].wr_id, wc[i].status,
						      0, &ts);
				if (ret) { ... }
			}
		}
	}
        // 获取结束时间
	if (gettimeofday(&end, NULL)) { ... }

	{
                // 计算并打印传输速率
		float usec = (end.tv_sec - start.tv_sec) * 1000000 +
			(end.tv_usec - start.tv_usec);
		long long bytes = (long long) size * iters * 2;

		printf("%lld bytes in %.2f seconds = %.2f Mbit/sec\n",
		       bytes, usec / 1000000., bytes * 8. / usec);
		printf("%d iters in %.2f seconds = %.2f usec/iter\n",
		       iters, usec / 1000000., usec / iters);
                ...
	}
        // 确认完成队列事件（Acknowledge Completion Queue Events）
	ibv_ack_cq_events(pp_cq(ctx), num_cq_events);
        // 关闭RDMA上下文
	if (pp_close_ctx(ctx))
		return 1;
        
        // 释放IB设备列表
	ibv_free_device_list(dev_list);
	free(rem_dest);

	return 0;        
}
```

编译后运行服务端和客户端，服务端运行结果如下：

```bash
$ ./ibv_rc_pingpong -g 2
  local address:  LID 0x0000, QPN 0x00001e, PSN 0x73a317, GID ::ffff:192.168.2.30
  remote address: LID 0x0000, QPN 0x00001f, PSN 0x0fd152, GID ::ffff:192.168.2.30
8192000 bytes in 0.06 seconds = 1059.73 Mbit/sec
1000 iters in 0.06 seconds = 61.84 usec/iter
```

客户端运行结果如下：

```bash
$ ./ibv_rc_pingpong -g 2 127.0.0.1
  local address:  LID 0x0000, QPN 0x00001f, PSN 0x0fd152, GID ::ffff:192.168.2.30
  remote address: LID 0x0000, QPN 0x00001e, PSN 0x73a317, GID ::ffff:192.168.2.30
8192000 bytes in 0.06 seconds = 1062.36 Mbit/sec
1000 iters in 0.06 seconds = 61.69 usec/iter
```

我们没有RDMA硬件，使用RoCEv2模拟RDMA设备。在运行程序之前需要先加载RoCEv2模块和驱动：

```bash
$ modprobe rdma_rxe
$ rdma link add rxe_0 type rxe netdev wlp7s0
```

我们可以使用`rdma link show`命令查看RoCEv2链接状态：

```bash
$ rdma link show 
link rxe_0/1 state ACTIVE physical_state LINK_UP netdev wlp7s0 
```

## 3 实现原理

### 3.1 获取RDMA设备列表

在示例程序中，我们需要指定RDMA设备名称，例如`rxe_0`。如果未指定设备名称，程序会默认使用系统中的第一个RDMA设备。我们通过调用`ibv_get_device_list()`函数获取系统中的RDMA设备列表，并遍历该列表来查找指定的设备。

`ibv_get_device_list`函数实现如下：

```c
// file: rdma-core/libibverbs/device.c
LATEST_SYMVER_FUNC(ibv_get_device_list, 1_1, "IBVERBS_1.1",
		   struct ibv_device **, int *num)
{
	struct ibv_device **l = NULL;
	struct verbs_device *device;
	static bool initialized;
	int num_devices;
	int i = 0;

	if (num) *num = 0;

	pthread_mutex_lock(&dev_list_lock);
        // ibverbs初始化，初始化log信息
	if (!initialized) {
		if (ibverbs_init()) goto out;
		initialized = true;
	}
        // 获取RDMA设备列表
	num_devices = ibverbs_get_device_list(&device_list);
	if (num_devices < 0) { ... }

	l = calloc(num_devices + 1, sizeof (struct ibv_device *));
	if (!l) { ... }
        // 遍历设备列表，转换为ibv_device
	list_for_each(&device_list, device, entry) {
		l[i] = &device->device;
		ibverbs_device_hold(l[i]);
		i++;
	}
	if (num) *num = num_devices;
out:
	pthread_mutex_unlock(&dev_list_lock);
	return l;
}
```

这其中核心的函数为`ibverbs_get_device_list`, 改函数首先尝试通过netlink获取RDMA设备列表，如果失败则尝试通过sysfs获取；然后根据获取到的设备列表，检查ABI版本，并尝试加载所有驱动程序；最后返回设备数量。其实现如下：

```c
// file: rdma-core/libibverbs/init.c
int ibverbs_get_device_list(struct list_head *device_list)
{
	LIST_HEAD(sysfs_list);
	struct verbs_sysfs_dev *sysfs_dev, *next_dev;
	struct verbs_device *vdev, *tmp;
	static int drivers_loaded;
	unsigned int num_devices = 0;
	int ret;

        // 通过netlink获取RDMA设备列表
	ret = find_sysfs_devs_nl(&sysfs_list);
	if (ret) {
                // 如果通过netlink获取失败，尝试通过sysfs获取
		ret = find_sysfs_devs(&sysfs_list);
		if (ret) return -ret;
	}

	if (!list_empty(&sysfs_list)) {
                // 检查ABI版本
		ret = check_abi_version();
		if (ret) return -ret;
	}

        // 根据`sysfs_list`遍历设备列表(`device_list`)，
        // 释放`sysfs_list`中在`device_list`中存在的设备，
        // 并从`device_list`中删除`sysfs_list`中不存在的设备
	list_for_each_safe(device_list, vdev, tmp, entry) {
                ...
	}
        // 尝试所有的驱动程序
	try_all_drivers(&sysfs_list, device_list, &num_devices);

	if (list_empty(&sysfs_list) || drivers_loaded)
		goto out;
        
        // 加载所有驱动程序
	load_drivers();
	drivers_loaded = 1;

	try_all_drivers(&sysfs_list, device_list, &num_devices);

out:
        // `sysfs_list`中剩余的设备，打印警告信息
	list_for_each_safe(&sysfs_list, sysfs_dev, next_dev, entry) {
		if (getenv("IBV_SHOW_WARNINGS")) { ... }
		free(sysfs_dev);
	}

	return num_devices;
}
```

#### 3.1.1 通过`sysfs`获取RDMA设备列表

我们只分析通过`sysfs`获取RDMA设备列表的情况。`find_sysfs_devs`函数通过读取`/sys/class/infiniband_verbs/`目录下的文件，获取RDMA设备列表。如下：

```c
// file: rdma-core/libibverbs/init.c
static int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *dev, *dev_tmp;
	char class_path[IBV_SYSFS_PATH_MAX];
	DIR *class_dir;
	struct dirent *dent;
	int ret = 0;

        // 获取`/sys/class/infiniband_verbs/`目录路径
	if (!check_snprintf(class_path, sizeof(class_path),
			    "%s/class/infiniband_verbs", ibv_get_sysfs_path()))
		return ENOMEM;

	class_dir = opendir(class_path);
	if (!class_dir) return ENOSYS;

	while ((dent = readdir(class_dir))) {
		if (dent->d_name[0] == '.') continue;
                // 设置`verbs_sysfs_dev`结构体
		ret = setup_sysfs_dev(dirfd(class_dir), dent->d_name, tmp_sysfs_dev_list);
		if (ret) break;
	}
	closedir(class_dir);

	if (ret) {
		list_for_each_safe (tmp_sysfs_dev_list, dev, dev_tmp, entry) { ... }
	}
	return ret;
}
```

我们通过`ls`查看系统的`/sys/class/infiniband_verbs/`目录，如下：

```bash
$ ls -al /sys/class/infiniband_verbs/
-r--r--r--  1 root root 4096 Feb 24 15:57 abi_version
lrwxrwxrwx  1 root root    0 Feb 24 15:57 uverbs0 -> ../../devices/virtual/infiniband_verbs/uverbs0
```

可以看到我们的RDMA设备为`uverbs0`。

#### 3.1.2 构建`sysfs`RDMA设备

`setup_sysfs_dev`函数构建`verbs_sysfs_dev`信息，从`/sys/class/infiniband/uverbs0`目录构建，如下：

```c
// file: rdma-core/libibverbs/init.c
static int setup_sysfs_dev(int dirfd, const char *uverbs,
			   struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *sysfs_dev = NULL;
	char value[32];
	int uv_dirfd;

	sysfs_dev = calloc(1, sizeof(*sysfs_dev));
	if (!sysfs_dev) return ENOMEM;

	sysfs_dev->ibdev_idx = -1;
        // 打开`/sys/class/infiniband/<uverbs>`目录
	uv_dirfd = openat(dirfd, uverbs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (uv_dirfd == -1) goto err_alloc;

        // 读取`/sys/class/infiniband_verbs/<uverbs>/ibdev`文件，获取RDMA设备名称
	if (ibv_read_sysfs_file_at(uv_dirfd, "ibdev", sysfs_dev->ibdev_name,
				   sizeof(sysfs_dev->ibdev_name)) < 0)
		goto err_fd;

        // 构建`/sys/class/infiniband/<ibdev_name>`路径
	if (!check_snprintf(
		    sysfs_dev->ibdev_path, sizeof(sysfs_dev->ibdev_path),
		    "%s/class/infiniband/%s", ibv_get_sysfs_path(),
		    sysfs_dev->ibdev_name))
		goto err_fd;

        // 从`/sys/class/infiniband_verbs/<uverbs>`目录，读取`dev`和`abi_version`文件
	if (setup_sysfs_uverbs(uv_dirfd, uverbs, sysfs_dev))
		goto err_fd;

        // 从`/sys/class/infiniband/<ibdev_name>`目录，读取`node_type`文件
	if (ibv_read_ibdev_sysfs_file(value, sizeof(value), sysfs_dev, "node_type") <= 0)
		sysfs_dev->node_type = IBV_NODE_UNKNOWN;
	else
		sysfs_dev->node_type = decode_knode_type(strtoul(value, NULL, 10));

	if (try_access_device(sysfs_dev))
		goto err_fd;

	close(uv_dirfd);
	list_add(tmp_sysfs_dev_list, &sysfs_dev->entry);
	return 0;

err_fd:
	close(uv_dirfd);
err_alloc:
	free(sysfs_dev);
	return 0;
}
```

#### 3.1.3 尝试创建RDMA设备

`try_all_drivers`函数尝试所有的驱动程序，创建RDMA设备。如下：

```c
// file: rdma-core/libibverbs/init.c
static void try_all_drivers(struct list_head *sysfs_list,
			    struct list_head *device_list,
			    unsigned int *num_devices)
{
	struct verbs_sysfs_dev *sysfs_dev;
	struct verbs_sysfs_dev *tmp;
	struct verbs_device *vdev;

	list_for_each_safe(sysfs_list, sysfs_dev, tmp, entry) {
                // 尝试所有的驱动程序
		vdev = try_drivers(sysfs_dev);
		if (vdev) {
                        // 从`sysfs_list`中删除成功创建的设备
			list_del(&sysfs_dev->entry);
			list_add(device_list, &vdev->entry);
			(*num_devices)++;
		}
	}
}
```

`try_drivers`函数尝试所有的驱动程序，创建RDMA设备。如下：

```c
// file: rdma-core/libibverbs/init.c
static struct verbs_device *try_drivers(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ibv_driver *driver;
	struct verbs_device *dev;

        // 尝试匹配`driver_id`
	if (sysfs_dev->driver_id != RDMA_DRIVER_UNKNOWN) {
                // 遍历所有的驱动程序，尝试匹配`driver_id`
		list_for_each (&driver_list, driver, entry) {
			if (match_driver_id(driver->ops, sysfs_dev)) {
				dev = try_driver(driver->ops, sysfs_dev);
				if (dev) return dev;
			}
		}
	}
        // 遍历所有的驱动程序，尝试匹配其他属性
	list_for_each(&driver_list, driver, entry) {
		dev = try_driver(driver->ops, sysfs_dev);
		if (dev) return dev;
	}
	return NULL;
}
```

`try_driver`函数尝试使用指定的驱动程序创建RDMA设备。如下：

```c
// file: rdma-core/libibverbs/init.c
static struct verbs_device *try_driver(const struct verbs_device_ops *ops,
				       struct verbs_sysfs_dev *sysfs_dev)
{
	struct verbs_device *vdev;
	struct ibv_device *dev;

        // 判断是否匹配驱动程序
	if (!match_device(ops, sysfs_dev)) return NULL;
        // 分配`verbs_device`设备
	vdev = ops->alloc_device(sysfs_dev);
	if (!vdev) { ... }

	vdev->ops = ops;

	atomic_init(&vdev->refcount, 1);
	dev = &vdev->device;
	assert(dev->_ops._dummy1 == NULL);
	assert(dev->_ops._dummy2 == NULL);

	dev->node_type = sysfs_dev->node_type;
        // 根据`node_type`设置`transport_type`
	switch (sysfs_dev->node_type) {
	case IBV_NODE_CA:
	case IBV_NODE_SWITCH:
	case IBV_NODE_ROUTER:
		dev->transport_type = IBV_TRANSPORT_IB;
		break;
	case IBV_NODE_RNIC:
		dev->transport_type = IBV_TRANSPORT_IWARP;
		break;
	case IBV_NODE_USNIC:
		dev->transport_type = IBV_TRANSPORT_USNIC;
		break;
	case IBV_NODE_USNIC_UDP:
		dev->transport_type = IBV_TRANSPORT_USNIC_UDP;
		break;
	case IBV_NODE_UNSPECIFIED:
		dev->transport_type = IBV_TRANSPORT_UNSPECIFIED;
		break;
	default:
		dev->transport_type = IBV_TRANSPORT_UNKNOWN;
		break;
	}

	strcpy(dev->dev_name,   sysfs_dev->sysfs_name);
        // 构建`/sys/class/infiniband_verbs/<sysfs_name>`路径
	if (!check_snprintf(dev->dev_path, sizeof(dev->dev_path),
			    "%s/class/infiniband_verbs/%s",
			    ibv_get_sysfs_path(), sysfs_dev->sysfs_name))
		goto err;
	strcpy(dev->name,       sysfs_dev->ibdev_name);
	strcpy(dev->ibdev_path, sysfs_dev->ibdev_path);
	vdev->sysfs = sysfs_dev;
	return vdev;

err:
	ops->uninit_device(vdev);
	return NULL;
}
```

#### 3.1.4 `rxe`初始化RDMA设备

我们使用`rxe`驱动模拟RDMA设备，用户空间对应的`struct verbs_device_ops`为`rxe_dev_ops`, 定义如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static const struct verbs_device_ops rxe_dev_ops = {
	.name = "rxe",
	.match_min_abi_version = sizeof(void *) == 8?1:2,
	.match_max_abi_version = 2,
	.match_table = hca_table,
	.alloc_device = rxe_device_alloc,
	.uninit_device = rxe_uninit_device,
	.alloc_context = rxe_alloc_context,
};
PROVIDER_DRIVER(rxe, rxe_dev_ops);
```

`PROVIDER_DRIVER`宏通过全局的构造函数，用于用户空间注册RDMA驱动程序。如下：

```c
// file: rdma-core/build/include/infiniband/driver.h
#define PROVIDER_DRIVER(provider_name, drv_struct)                             \
	extern const struct verbs_device_ops verbs_provider_##provider_name    \
		__attribute__((alias(stringify(drv_struct))));                 \
	static __attribute__((constructor)) void provider_name##_register_driver(void) \
	{                                                                      \
		verbs_register_driver(&drv_struct);                            \
	}
```

`verbs_register_driver`函数用于注册RDMA驱动程序。如下：

```c
// file: rdma-core/libibverbs/init.c
void verbs_register_driver(const struct verbs_device_ops *ops)
{
	struct ibv_driver *driver;

	driver = malloc(sizeof *driver);
	if (!driver) { ... }
	driver->ops = ops;
        // 将驱动程序添加到`driver_list`链表中
	list_add_tail(&driver_list, &driver->entry);
}
```

通过`rxe_dev_ops`驱动可以看到，`rxe`驱动程序的匹配属性为`hca_table`，定义如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_RXE),
	VERBS_NAME_MATCH("rxe", NULL),
	{},
};
```

可以看到，`rxe`可以通过`DRIVER_ID`和`NAME`来匹配设备。

`.alloc_device`接口设置为`rxe_device_alloc`, 用于分配`rxe_device`设备。如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct verbs_device *rxe_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct rxe_device *dev;
        // 分配`rxe_device`结构体
	dev = calloc(1, sizeof(*dev));
	if (!dev) return NULL;
        // 设置`rxe_device`的ABI版本
	dev->abi_version = sysfs_dev->abi_ver;
	return &dev->ibv_dev;
}
```

### 3.2 内核空间`rxe`设备初始化

#### 3.2.1 `rxe`模块初始化

前一章节我们介绍了用户空间的RDMA设备的初始化过程，接下来我们介绍内核空间的`rxe`设备初始化过程，在运行示例程序之前需要先加载`rxe`驱动程序：

```bash
$ modprobe rdma_rxe
```

`rdma_rxe`模块的初始化函数为`rxe_module_init`, 定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
static int __init rxe_module_init(void)
{
	int err;
        // 分配`rxe`工作队列
	err = rxe_alloc_wq();
	if (err) return err;
        // 初始化`rxe`网络设备
	err = rxe_net_init();
	if (err) { ... }
        // 注册`rxe`链接操作
	rdma_link_register(&rxe_link_ops);
	pr_info("loaded\n");
	return 0;
}
late_initcall(rxe_module_init);
```

`rdma_link_register`函数用于注册`rxe`链接操作，实现如下：

```c
// file: drivers/infiniband/core/nldev.c
void rdma_link_register(struct rdma_link_ops *ops)
{
	down_write(&link_ops_rwsem);
	if (WARN_ON_ONCE(link_ops_get(ops->type)))
		goto out;
        // 添加到`link_ops`链表中
	list_add(&ops->list, &link_ops);
out:
	up_write(&link_ops_rwsem);
}
```

`rxe_link_ops`为`rxe`链接操作，定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
static struct rdma_link_ops rxe_link_ops = {
	.type = "rxe",
	.newlink = rxe_newlink,
};
```

#### 3.2.2 创建`rxe`设备

在加载`rdma_rxe`模块后，通过`rdma link add`命令可以创建`rxe`设备。如下：

```bash
$ rdma link add rxe_0 type rxe netdev wlp7s0
```

`rdma`程序通过`netlink`和内核通信，`rdma link add`命令对应`nldev_newlink`，实现如下：

```c
// file: drivers/infiniband/core/nldev.c
static int nldev_newlink(struct sk_buff *skb, struct nlmsghdr *nlh,
			  struct netlink_ext_ack *extack)
{
        ...
        // 通过设备名称获取`net_device`结构体
	ndev = dev_get_by_name(sock_net(skb->sk), ndev_name);
	if (!ndev) return -ENODEV;

	down_read(&link_ops_rwsem);
        // 获取`rdma_link_ops`结构体
	ops = link_ops_get(type);
        ...
        // 创建新的`link`
	err = ops ? ops->newlink(ibdev_name, ndev) : -EINVAL;
	up_read(&link_ops_rwsem);
	dev_put(ndev);

	return err;
}
```

`rxe`设置的`.newlink`接口为`rxe_newlink`, 实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
static int rxe_newlink(const char *ibdev_name, struct net_device *ndev)
{
	struct rxe_dev *rxe;
        ...
        // 检查`net_device`是否已经配置了`rxe`设备
	rxe = rxe_get_dev_from_net(ndev);
	if (rxe) { ... }

        // 创建新的`rxe`设备
	err = rxe_net_add(ibdev_name, ndev);
	if (err) { ... }
err:
	return err;
}
```

`rxe_net_add`函数用于创建新的`rxe`设备，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
int rxe_net_add(const char *ibdev_name, struct net_device *ndev)
{
	int err;
	struct rxe_dev *rxe = NULL;
        // 分配`rxe_dev`结构体
	rxe = ib_alloc_device(rxe_dev, ib_dev);
	if (!rxe) return -ENOMEM;

	ib_mark_name_assigned_by_user(&rxe->ib_dev);
        // 添加`rxe`设备
	err = rxe_add(rxe, ndev->mtu, ibdev_name, ndev);
	if (err) { ... }
	return 0;
}
```

`rxe_add`函数在分配`rxe_dev`结构体后，添加`rxe`设备，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
int rxe_add(struct rxe_dev *rxe, unsigned int mtu, const char *ibdev_name,
			struct net_device *ndev)
{
	rxe_init(rxe, ndev);
	rxe_set_mtu(rxe, mtu);

	return rxe_register_device(rxe, ibdev_name, ndev);
}
```

`rxe_init`函数用于初始化`rxe_dev`设备、端口参数及`pool`，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
static void rxe_init(struct rxe_dev *rxe, struct net_device *ndev)
{
        // 初始化`rxe_dev`设备参数
	rxe_init_device_param(rxe, ndev);
        // 初始化`rxe_dev`端口参数
	rxe_init_ports(rxe, ndev);
        // 初始化`rxe_dev`的`pool`
	rxe_init_pools(rxe);
        // 初始化`rxe_dev`的`pending_mmaps`链表
	spin_lock_init(&rxe->mmap_offset_lock);
	spin_lock_init(&rxe->pending_lock);
	INIT_LIST_HEAD(&rxe->pending_mmaps);

	spin_lock_init(&rxe->mcg_lock);
	rxe->mcg_tree = RB_ROOT;

	mutex_init(&rxe->usdev_lock);
}
```

`rxe_register_device`函数用于注册`rxe_dev`设备，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
int rxe_register_device(struct rxe_dev *rxe, const char *ibdev_name,
						struct net_device *ndev)
{
	int err;
	struct ib_device *dev = &rxe->ib_dev;
        // 设置`rxe_dev`设备描述符
	strscpy(dev->node_desc, "rxe", sizeof(dev->node_desc));

	dev->node_type = RDMA_NODE_IB_CA;
	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = num_possible_cpus();
	dev->local_dma_lkey = 0;
	addrconf_addr_eui48((unsigned char *)&dev->node_guid, rxe->raw_gid);

	dev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
				BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ);
        // 设置`rxe_dev`设备操作函数
	ib_set_device_ops(dev, &rxe_dev_ops);
        // 将`rxe_dev`设备关联到`net_device`
	err = ib_device_set_netdev(&rxe->ib_dev, ndev, 1);
	if (err) return err;
        // 注册`rxe_dev`设备
	err = ib_register_device(dev, ibdev_name, NULL);
	if (err) rxe_dbg_dev(rxe, "failed with error %d\n", err);

	return err;
}
```

`rxe`设置的操作接口为`rxe_dev_ops`，定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static const struct ib_device_ops rxe_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_RXE,
	.uverbs_abi_ver = RXE_UVERBS_ABI_VERSION,
        ...
};
```

### 3.3 打开`ibv`设备

#### 3.3.1 用户空间相关操作

在用户空间，示例程序通过`pp_init_ctx`函数打开`ibv`设备，核心代码如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
	struct pingpong_context *ctx;
	int access_flags = IBV_ACCESS_LOCAL_WRITE;

	ctx = calloc(1, sizeof *ctx);
	if (!ctx) return NULL;

	ctx->size       = size;
	ctx->send_flags = IBV_SEND_SIGNALED;
	ctx->rx_depth   = rx_depth;
        // 分配工作缓冲区
	ctx->buf = memalign(page_size, size);
	if (!ctx->buf) { ... }

	memset(ctx->buf, 0x7b, size);
        // 打开`ibv`设备
	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) { ... }
        ...
}
```

用户空间通过`ibv_open_device`函数打开`ibv`设备，是对`verbs_open_device`函数的封装，实现如下：

```c
// file: rdma-core/libibverbs/device.c
LATEST_SYMVER_FUNC(ibv_open_device, 1_1, "IBVERBS_1.1",
		   struct ibv_context *,
		   struct ibv_device *device)
{
	return verbs_open_device(device, NULL);
}
```

`verbs_open_device`函数用于打开`ibv`设备，实现如下：

```c
// file: rdma-core/libibverbs/device.c
struct ibv_context *verbs_open_device(struct ibv_device *device, void *private_data)
{
	struct verbs_device *verbs_device = verbs_get_device(device);
        ...

	if (verbs_device->sysfs) {
                // 打开`ibv`设备的`cmd_fd`
		cmd_fd = open_cdev(verbs_device->sysfs->sysfs_name,
				   verbs_device->sysfs->sysfs_cdev);
		if (cmd_fd < 0) return NULL;
	}

        // 调用`.alloc_context`接口分配`verbs_context`
	context_ex = verbs_device->ops->alloc_context(device, cmd_fd, private_data);
	if (!context_ex) return NULL;

        // 设置`verbs_context`的操作函数
	set_lib_ops(context_ex);
	if (verbs_device->sysfs) {
                // 初始化`verbs_context`的异步事件文件描述符
                ...
	}
	return &context_ex->context;
}
```

`open_cdev`函数用于打开`ibv`设备的`cmd_fd`，实现如下：

```c
// file: rdma-core/util/open_cdev.c
int open_cdev(const char *devname_hint, dev_t cdev)
{
	char *devpath;
	int fd;
        // `RDMA_CDEV_DIR`为`/dev/infiniband`
	if (asprintf(&devpath, RDMA_CDEV_DIR "/%s", devname_hint) < 0)
		return -1;
        // 打开`ibv`设备
	fd = open_cdev_internal(devpath, cdev);
	free(devpath);
	if (fd == -1 && cdev != 0)
		return open_cdev_robust(devname_hint, cdev);
	return fd;
}
```

#### 3.3.2 `rxe`用户空间创建`verbs_context`

`rxe`设置的`.alloc_context`接口为`rxe_alloc_context`, 如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static const struct verbs_device_ops rxe_dev_ops = {
	.name = "rxe",
        ...
	.alloc_context = rxe_alloc_context,
};
```

实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct verbs_context *rxe_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd,
					       void *private_data)
{
	struct rxe_context *context;
	struct ibv_get_context cmd;
	struct ib_uverbs_get_context_resp resp;

        // 创建并初始化`verbs_context`
	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_RXE);
	if (!context) return NULL;
        // 通过`ibv_cmd`获取`verbs_context`的上下文
	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				NULL, &resp, sizeof(resp)))
		goto out;
        // 设置`verbs_context`的操作函数
	verbs_set_ops(&context->ibv_ctx, &rxe_ctx_ops);
        // 返回`verbs_context`
	return &context->ibv_ctx;
out:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}
```

##### 1. 创建并初始化`verbs_context`

`verbs_init_and_alloc_context`函数用于创建并初始化`verbs_context`，是对`_verbs_init_and_alloc_context`函数的封装，后者实现如下：

```c
// file: rdma-core/libibverbs/device.c
void *_verbs_init_and_alloc_context(struct ibv_device *device, int cmd_fd,
				    size_t alloc_size,
				    struct verbs_context *context_offset,
				    uint32_t driver_id)
{
	void *drv_context;
	struct verbs_context *context;
        // 分配`verbs_context`的内存
	drv_context = calloc(1, alloc_size);
	if (!drv_context) { ...	}

	context = drv_context + (uintptr_t)context_offset;
        // 初始化`verbs_context`
	if (verbs_init_context(context, device, cmd_fd, driver_id))
		goto err_free;

	return drv_context;

err_free:
	free(drv_context);
	return NULL;
}
```

`verbs_init_context`函数用于初始化`verbs_context`，设置`.context`相关字段，实现如下：

```c
// file: rdma-core/libibverbs/device.c
int verbs_init_context(struct verbs_context *context_ex,
		       struct ibv_device *device, int cmd_fd,
		       uint32_t driver_id)
{
	struct ibv_context *context = &context_ex->context;

	ibverbs_device_hold(device);
        // 设置`verbs_context`的相关字段
	context->device = device;
	context->cmd_fd = cmd_fd;
	context->async_fd = -1;
	pthread_mutex_init(&context->mutex, NULL);

	context_ex->context.abi_compat = __VERBS_ABI_IS_EXTENDED;
	context_ex->sz = sizeof(*context_ex);
        // 分配`verbs_context`的私有数据
	context_ex->priv = calloc(1, sizeof(*context_ex->priv));
	if (!context_ex->priv) { ... }

        // 设置`verbs_context`的私有数据
	context_ex->priv->driver_id = driver_id;
	verbs_set_ops(context_ex, &verbs_dummy_ops);
	context_ex->priv->use_ioctl_write = has_ioctl_write(context);
	return 0;
}
```

##### 2. 获取`verbs_context`

`ibv_cmd_get_context`函数用于获取`verbs_context`，实现如下：

```c
// file: rdma-core/libibverbs/cmd_device.c
int ibv_cmd_get_context(struct verbs_context *context_ex,
			struct ibv_get_context *cmd, size_t cmd_size,
			struct ibv_fd_arr *fd_arr,
			struct ib_uverbs_get_context_resp *resp,
			size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_DEVICE,
				  UVERBS_METHOD_GET_CONTEXT, cmd, cmd_size,
				  resp, resp_size);

	return cmd_get_context(context_ex, fd_arr, cmdb);
}
```

`cmd_get_context`函数用于通过`ioctl`或者`write`两种方式获取`verbs_context`的上下文，实现如下：

```c
// file: rdma-core/libibverbs/cmd_device.c
static int cmd_get_context(struct verbs_context *context_ex,
			   struct ibv_fd_arr *fds,
			   struct ibv_command_buffer *link)
{
        // 创建`ibv_command_buffer`
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			     UVERBS_METHOD_GET_CONTEXT, 3, link);

	struct ibv_context *context = &context_ex->context;
	struct verbs_device *verbs_device;
	uint64_t core_support;
	uint32_t num_comp_vectors;
	int ret;

        // 设置`verbs_context`的上下文相关字段
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS, &num_comp_vectors);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT, &core_support);
	if (fds)
		fill_attr_in_ptr_array(cmdb, UVERBS_ATTR_GET_CONTEXT_FD_ARR, fds->arr, fds->count);

        // 通过`ioctl`获取`verbs_context`的上下文
	switch (execute_ioctl_fallback(context, free_context, cmdb, &ret)) {
	case TRY_WRITE: {
		DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_GET_CONTEXT);

                // 通过`write`获取`verbs_context`的上下文
		ret = execute_write_bufs(context, IB_USER_VERBS_CMD_GET_CONTEXT, req, resp);
		if (ret) return ret;
                // 设置`verbs_context`的上下文相关字段
		context->async_fd = resp->async_fd;
		context->num_comp_vectors = resp->num_comp_vectors;
		return 0;
	}
        ...
	};
        // 设置`verbs_context`的上下文相关字段
	context->num_comp_vectors = num_comp_vectors;
	verbs_device = verbs_get_device(context->device);
	verbs_device->core_support = core_support;
	return 0;
}
```

#### 3.3.3 `rxe`内核空间获取上下文

##### 1. 内核空间接口

我们略过用户空间和内核空间通过`ioctl`或者`write`两种方式交互的过程，只关心用户空间和内核空间的相关操作。内核空间`UVERBS_METHOD_GET_CONTEXT`对应的处理函数为`rxe_get_context`, 定义如下：

```c
// file: drivers/infiniband/core/uverbs_std_types_device.c
static int UVERBS_HANDLER(UVERBS_METHOD_GET_CONTEXT)(
	struct uverbs_attr_bundle *attrs)
{
	u32 num_comp = attrs->ufile->device->num_comp_vectors;
	u64 core_support = IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS;
	int ret;

        // 复制`num_comp_vectors`到用户空间
	ret = uverbs_copy_to(attrs, UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS,
			     &num_comp, sizeof(num_comp));
	if (IS_UVERBS_COPY_ERR(ret)) return ret;
	ret = uverbs_copy_to(attrs, UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT,
			     &core_support, sizeof(core_support));
	if (IS_UVERBS_COPY_ERR(ret)) return ret;
        
        // 分配并初始化`verbs_ucontext`
	ret = ib_alloc_ucontext(attrs);
	if (ret) return ret;
	// 初始化`verbs_context`
        ret = ib_init_ucontext(attrs);
	if (ret) { ... }
	return 0;
}
```

`ib_alloc_ucontext`函数用于分配`verbs_ucontext`，实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
int ib_alloc_ucontext(struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_file *ufile = attrs->ufile;
	struct ib_ucontext *ucontext;
	struct ib_device *ib_dev;
        // 从`ib_uverbs_file`中获取`ib_device`
	ib_dev = srcu_dereference(ufile->device->ib_dev,
				  &ufile->device->disassociate_srcu);
	if (!ib_dev) return -EIO;
        // 从`ib_device`中分配`verbs_ucontext`
	ucontext = rdma_zalloc_drv_obj(ib_dev, ib_ucontext);
	if (!ucontext) return -ENOMEM;

	ucontext->device = ib_dev;
	ucontext->ufile = ufile;
	xa_init_flags(&ucontext->mmap_xa, XA_FLAGS_ALLOC);

	rdma_restrack_new(&ucontext->res, RDMA_RESTRACK_CTX);
	rdma_restrack_set_name(&ucontext->res, NULL);
	attrs->context = ucontext;
	return 0;
}
```

`ib_init_ucontext`函数用于初始化`verbs_ucontext`，调用`ib_device`的`.alloc_ucontext`方法分配`verbs_ucontext`，实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
int ib_init_ucontext(struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = attrs->context;
	struct ib_uverbs_file *file = attrs->ufile;

        ...
        // 调用`.alloc_ucontext`接口分配`verbs_ucontext`
	ret = ucontext->device->ops.alloc_ucontext(ucontext, &attrs->driver_udata);
	if (ret) goto err_uncharge;

	rdma_restrack_add(&ucontext->res);
	smp_store_release(&file->ucontext, ucontext);

	mutex_unlock(&file->ucontext_lock);
	up_read(&file->hw_destroy_rwsem);
	return 0;
        ...
}
```

##### 2. `rxe`内核空间创建上下文

`rxe`设置的`.alloc_ucontext`接口为`rxe_alloc_ucontext`, 其定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static const struct ib_device_ops rxe_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_RXE,
	.uverbs_abi_ver = RXE_UVERBS_ABI_VERSION,
        ...
	.alloc_ucontext = rxe_alloc_ucontext,
        ...
};
```

其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static int rxe_alloc_ucontext(struct ib_ucontext *ibuc, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibuc->device);
	struct rxe_ucontext *uc = to_ruc(ibuc);
        int err;
        // 向`rxe`的`uc_pool`中添加`uc`
	err = rxe_add_to_pool(&rxe->uc_pool, uc);
	if (err)
		rxe_err_dev(rxe, "unable to create uc\n");

	return err;
}
```

### 3.4 创建`pd`

`pd`(Protection Domain)用于保护`verbs`中的资源不被其他`verbs`使用。用户空间通过`ibv_alloc_pd`函数创建`pd`，实现如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
        ...
        // 打开`ib_dev`，获取`verbs_context`
        ctx->context = ibv_open_device(ib_dev);
        ...
        // 分配`pd`
        ctx->pd = ibv_alloc_pd(ctx->context);
        ...
}
```

`ibv_alloc_pd`函数用于分配`pd`，调用对应的`.alloc_pd`接口，实现如下：

```c
// file: rdma-core/libibverbs/verbs.c
LATEST_SYMVER_FUNC(ibv_alloc_pd, 1_1, "IBVERBS_1.1",
		   struct ibv_pd *,
		   struct ibv_context *context)
{
	struct ibv_pd *pd;
        // 调用`ib_device`的`.alloc_pd`方法分配`pd`
	pd = get_ops(context)->alloc_pd(context);
	if (pd)
		pd->context = context;
	return pd;
}
```

#### 3.4.1 用户空间`rxe`创建`pd`

`rxe`设置的`.alloc_pd`接口为`rxe_alloc_pd`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct ibv_pd *rxe_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

        // 分配`pd`
	pd = calloc(1, sizeof(*pd));
	if (!pd) return NULL;
        // 调用`ibv_cmd_alloc_pd`分配`pd`
	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof(cmd),
					&resp, sizeof(resp))) { ... }
	return pd;
}
```

`ibv_cmd_alloc_pd`函数通过`write`系统调用与内核交互，实现分配`pd`的功能。实现如下：

```c
// file: rdma-core/libibverbs/cmd.c
int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ib_uverbs_alloc_pd_resp *resp, size_t resp_size)
{
	int ret;
        // 通过`IB_USER_VERBS_CMD_ALLOC_PD`命令创建`pd`
	ret = execute_cmd_write(context, IB_USER_VERBS_CMD_ALLOC_PD, cmd,
				cmd_size, resp, resp_size);
	if (ret) return ret;
        // 设置`pd`的`handle`和`context`
	pd->handle  = resp->pd_handle;
	pd->context = context;
	return 0;
}
```

#### 3.4.2 内核空间创建`pd`

`IB_USER_VERBS_CMD_ALLOC_PD`对应的内核空间处理函数为`ib_uverbs_alloc_pd`, 如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
const struct uapi_definition uverbs_def_write_intf[] = {
        ...
	DECLARE_UVERBS_OBJECT(
		UVERBS_OBJECT_PD,
		DECLARE_UVERBS_WRITE(
			IB_USER_VERBS_CMD_ALLOC_PD,
			ib_uverbs_alloc_pd,
			UAPI_DEF_WRITE_UDATA_IO(struct ib_uverbs_alloc_pd,
						struct ib_uverbs_alloc_pd_resp),
			UAPI_DEF_METHOD_NEEDS_FN(alloc_pd)),
        ...
};
```

其实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
static int ib_uverbs_alloc_pd(struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_alloc_pd_resp resp = {};
	struct ib_uverbs_alloc_pd      cmd;
	struct ib_uobject             *uobj;
	struct ib_pd                  *pd;
	int                            ret;
	struct ib_device *ib_dev;

        // 从`attrs`中获取`cmd`
	ret = uverbs_request(attrs, &cmd, sizeof(cmd));
	if (ret) return ret;
        // 分配`uobj`
	uobj = uobj_alloc(UVERBS_OBJECT_PD, attrs, &ib_dev);
	if (IS_ERR(uobj)) return PTR_ERR(uobj);
        // 分配`pd`
	pd = rdma_zalloc_drv_obj(ib_dev, ib_pd);
	if (!pd) { ... }

	pd->device  = ib_dev;
	pd->uobject = uobj;
	atomic_set(&pd->usecnt, 0);

	rdma_restrack_new(&pd->res, RDMA_RESTRACK_PD);
	rdma_restrack_set_name(&pd->res, NULL);

        // 调用`ib_dev`的`.alloc_pd`方法分配`pd`
	ret = ib_dev->ops.alloc_pd(pd, &attrs->driver_udata);
	if (ret) goto err_alloc;
	rdma_restrack_add(&pd->res);

	uobj->object = pd;
	uobj_finalize_uobj_create(uobj, attrs);

        // 设置回复结果
	resp.pd_handle = uobj->id;
        // 返回`resp`
	return uverbs_response(attrs, &resp, sizeof(resp));

err_alloc:
	rdma_restrack_put(&pd->res);
	kfree(pd);
err:
	uobj_alloc_abort(uobj, attrs);
	return ret;
}
```

#### 3.4.3 内核空间`rxe`创建`pd`

`rxe`的`.alloc_pd`方法为`rxe_alloc_pd`, 其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static int rxe_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	int err;
        // 将`pd`添加到`rxe`的`pd_pool`中
	err = rxe_add_to_pool(&rxe->pd_pool, pd);
	if (err) { ... }

	return 0;
        ...
}
```

### 3.5 注册`mr`

`mr`(Memory Region)表示用户空间内存的一个区域，用于存放收发的数据。用户空间通过`ibv_reg_mr`函数注册`mr`，实现如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
        ...
        // 分配`mr`
	if (implicit_odp) {
		ctx->mr = ibv_reg_mr(ctx->pd, NULL, SIZE_MAX, access_flags);
	} else {
                // 如果使用`dm`，则注册`dm_mr`，否则注册普通`mr`
		ctx->mr = use_dm ? ibv_reg_dm_mr(ctx->pd, ctx->dm, 0, size, access_flags) :
			ibv_reg_mr(ctx->pd, ctx->buf, size, access_flags);
	}
        ...
}
```

`ibv_reg_mr`函数用于注册`mr`，是对`ibv_reg_mr_iova2`函数的封装，如下：

```c
// file: rdma-core/libibverbs/verbs.c
LATEST_SYMVER_FUNC(ibv_reg_mr, 1_1, "IBVERBS_1.1",
		   struct ibv_mr *,
		   struct ibv_pd *pd, void *addr,
		   size_t length, int access)
{
	return ibv_reg_mr_iova2(pd, addr, length, (uintptr_t)addr, access);
}
```

`ibv_reg_mr_iova2`函数用于注册`mr`，调用对应的`.reg_mr`接口，实现如下：

```c
// file: rdma-core/libibverbs/verbs.c
struct ibv_mr *ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
				uint64_t iova, unsigned int access)
{
	struct verbs_device *device = verbs_get_device(pd->context->device);
	bool odp_mr = access & IBV_ACCESS_ON_DEMAND;
	struct ibv_mr *mr;

	if (!(device->core_support & IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS))
		access &= ~IBV_ACCESS_OPTIONAL_RANGE;

	if (!odp_mr && ibv_dontfork_range(addr, length))
		return NULL;

        // 调用`.reg_mr`方法注册`mr`
	mr = get_ops(pd->context)->reg_mr(pd, addr, length, iova, access);
	if (mr) {
                // 设置`mr`的`context`、`pd`、`addr`、`length`
		mr->context = pd->context;
		mr->pd      = pd;
		mr->addr    = addr;
		mr->length  = length;
	} else {
		if (!odp_mr)
			ibv_dofork_range(addr, length);
	}

	return mr;
}
```

#### 3.5.1 用户空间`rxe`注册`mr`

`rxe`设置的`.reg_mr`接口为`rxe_reg_mr`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct ibv_mr *rxe_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

        // 分配`vmr`
	vmr = calloc(1, sizeof(*vmr));
	if (!vmr) return NULL;

        // 调用`ibv_cmd_reg_mr`注册`mr`
	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) { ... }
        // 返回`ibv_mr`
	return &vmr->ibv_mr;
}
```

`ibv_cmd_reg_mr`函数通过`IB_USER_VERBS_CMD_REG_MR`命令注册`mr`后，获取`mr`的`handle`,`lkey`和`rkey`，并设置到`vmr`中，如下：

```c
// file: rdma-core/libibverbs/cmd.c
int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, int access,
		   struct verbs_mr *vmr, struct ibv_reg_mr *cmd,
		   size_t cmd_size,
		   struct ib_uverbs_reg_mr_resp *resp, size_t resp_size)
{
	int ret;
        // 设置`cmd`的相关字段
	cmd->start 	  = (uintptr_t) addr;
	cmd->length 	  = length;
        // 检查按需访问的情况
	if (access & IBV_ACCESS_ON_DEMAND) { ... }
        // 设置`cmd`的其他字段
	cmd->hca_va 	  = hca_va;
	cmd->pd_handle 	  = pd->handle;
	cmd->access_flags = access;
        // 执行`IB_USER_VERBS_CMD_REG_MR`命令
	ret = execute_cmd_write(pd->context, IB_USER_VERBS_CMD_REG_MR, cmd,
				cmd_size, resp, resp_size);
	if (ret) return ret;

        // 设置`vmr`的相关字段
	vmr->ibv_mr.handle  = resp->mr_handle;
	vmr->ibv_mr.lkey    = resp->lkey;
	vmr->ibv_mr.rkey    = resp->rkey;
	vmr->ibv_mr.context = pd->context;
	vmr->mr_type        = IBV_MR_TYPE_MR;
	vmr->access = access;
	return 0;
}
```

#### 3.5.2 内核空间注册`mr`

`IB_USER_VERBS_CMD_REG_MR`对应的内核空间处理函数为`ib_uverbs_reg_mr`, 如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
const struct uapi_definition uverbs_def_write_intf[] = {
        ...
	DECLARE_UVERBS_OBJECT(
		UVERBS_OBJECT_MR,
                ...
		DECLARE_UVERBS_WRITE(
			IB_USER_VERBS_CMD_REG_MR,
			ib_uverbs_reg_mr,
			UAPI_DEF_WRITE_UDATA_IO(struct ib_uverbs_reg_mr,
						struct ib_uverbs_reg_mr_resp),
			UAPI_DEF_METHOD_NEEDS_FN(reg_user_mr)),
                ...
        ...
};
```

其实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
static int ib_uverbs_reg_mr(struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_reg_mr_resp resp = {};
	struct ib_uverbs_reg_mr      cmd;
	struct ib_uobject           *uobj;
	struct ib_pd                *pd;
	struct ib_mr                *mr;
	int                          ret;
	struct ib_device *ib_dev;

        // 获取`cmd`
	ret = uverbs_request(attrs, &cmd, sizeof(cmd));
	if (ret) return ret;
        // 检查`cmd`的`start`和`hca_va`是否对齐到`PAGE_SIZE`
	if ((cmd.start & ~PAGE_MASK) != (cmd.hca_va & ~PAGE_MASK)) return -EINVAL;
        // 分配`uobj`
	uobj = uobj_alloc(UVERBS_OBJECT_MR, attrs, &ib_dev);
	if (IS_ERR(uobj)) return PTR_ERR(uobj);
        // 检查`access_flags`是否合法
	ret = ib_check_mr_access(ib_dev, cmd.access_flags);
	if (ret) goto err_free;
        // 获取`pd`
	pd = uobj_get_obj_read(pd, UVERBS_OBJECT_PD, cmd.pd_handle, attrs);
	if (IS_ERR(pd)) { ...  }

        // 调用`.reg_user_mr`方法注册`mr`
	mr = pd->device->ops.reg_user_mr(pd, cmd.start, cmd.length, cmd.hca_va,
					 cmd.access_flags, NULL,
					 &attrs->driver_udata);
	if (IS_ERR(mr)) { ...  }

        // 设置`mr`的相关字段
	mr->device  = pd->device;
	mr->pd      = pd;
	mr->type    = IB_MR_TYPE_USER;
	mr->dm	    = NULL;
	mr->sig_attrs = NULL;
	mr->uobject = uobj;
	atomic_inc(&pd->usecnt);
        // 设置`mr`的`iova`、`length`
	mr->iova = cmd.hca_va;
	mr->length = cmd.length;

	rdma_restrack_new(&mr->res, RDMA_RESTRACK_MR);
	rdma_restrack_set_name(&mr->res, NULL);
	rdma_restrack_add(&mr->res);

	uobj->object = mr;
	uobj_put_obj_read(pd);
	uobj_finalize_uobj_create(uobj, attrs);

        // 设置`resp`的相关字段
	resp.lkey = mr->lkey;
	resp.rkey = mr->rkey;
	resp.mr_handle = uobj->id;
	return uverbs_response(attrs, &resp, sizeof(resp));

err_put:
	uobj_put_obj_read(pd);
err_free:
	uobj_alloc_abort(uobj, attrs);
	return ret;
}
```

#### 3.5.3 内核空间`rxe`注册`mr`

`rxe`设置的`.reg_user_mr`接口为`rxe_reg_user_mr`, 其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static struct ib_mr *rxe_reg_user_mr(struct ib_pd *ibpd, u64 start,
				     u64 length, u64 iova, int access,
				     struct ib_dmah *dmah,
				     struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mr *mr;
	int err, cleanup_err;

	if (dmah) return ERR_PTR(-EOPNOTSUPP);
        // 检查`access`是否合法
	if (access & ~RXE_ACCESS_SUPPORTED_MR) { ... }
        // 分配`mr`
	mr = kzalloc_obj(*mr);
	if (!mr) return ERR_PTR(-ENOMEM);

        // 添加到`mr_pool`中
	err = rxe_add_to_pool(&rxe->mr_pool, mr);
	if (err) { ... }

	rxe_get(pd);
	mr->ibmr.pd = ibpd;
	mr->ibmr.device = ibpd->device;

	if (access & IB_ACCESS_ON_DEMAND)
		err = rxe_odp_mr_init_user(rxe, start, length, iova, access, mr);
	else
		err = rxe_mr_init_user(rxe, start, length, access, mr);
	if (err) { ... }

	rxe_finalize(mr);
	return &mr->ibmr;
        ...
}
```

我们只需要关注`rxe_mr_init_user`函数，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_mr.c
int rxe_mr_init_user(struct rxe_dev *rxe, u64 start, u64 length,
		     int access, struct rxe_mr *mr)
{
	struct ib_umem *umem;
	int err;
        // 初始化`mr`
	rxe_mr_init(access, mr);
        // 获取`umem`
	umem = ib_umem_get(&rxe->ib_dev, start, length, access);
	if (IS_ERR(umem)) { ... }
        // 分配`mr`的`page_info`
	err = alloc_mr_page_info(mr, ib_umem_num_pages(umem));
	if (err) goto err2;
        // 填充`mr`的`page_info`
	err = rxe_mr_fill_pages_from_sgt(mr, &umem->sgt_append.sgt);
	if (err) goto err1;

        // 设置`mr`的`umem`、`type`、`state`
	mr->umem = umem;
	mr->ibmr.type = IB_MR_TYPE_USER;
	mr->state = RXE_MR_STATE_VALID;
	return 0;
err1:
	free_mr_page_info(mr);
err2:
	ib_umem_release(umem);
	return err;
}
```

`rxe_mr_init`初始化`mr`的相关字段，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_mr.c
void rxe_mr_init(int access, struct rxe_mr *mr)
{
        // 生成`mr`的`key`
	u32 key = mr->elem.index << 8 | rxe_get_next_key(-1);
        // 设置`mr`的`lkey`,`rkey`
	mr->lkey = mr->ibmr.lkey = key;
	mr->rkey = mr->ibmr.rkey = key;
        // 设置`mr`相关字段
	mr->access = access;
	mr->ibmr.page_size = PAGE_SIZE;
	mr->page_mask = PAGE_MASK;
	mr->page_shift = PAGE_SHIFT;
	mr->state = RXE_MR_STATE_INVALID;
}
```

### 3.6 创建`cq`

`cq`(Completion Queue)用于通知用户空间操作完成。用户空间通过`ibv_create_cq`函数创建`cq`，实现如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
        ...
	if (use_ts) {
		struct ibv_cq_init_attr_ex attr_ex = {
			.cqe = rx_depth + 1,
			.cq_context = NULL,
			.channel = ctx->channel,
			.comp_vector = 0,
			.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP
		};
                // 创建`cq_ex`
		ctx->cq_s.cq_ex = ibv_create_cq_ex(ctx->context, &attr_ex);
	} else {
                // 创建`cq`
		ctx->cq_s.cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL,
					     ctx->channel, 0);
	}
        ...
}
```

`ibv_create_cq`函数用于创建`cq`，调用对应的`.create_cq`接口，实现如下：

```c
// file: rdma-core/libibverbs/verbs.c
LATEST_SYMVER_FUNC(ibv_create_cq, 1_1, "IBVERBS_1.1",
		   struct ibv_cq *,
		   struct ibv_context *context, int cqe, void *cq_context,
		   struct ibv_comp_channel *channel, int comp_vector)
{
	struct ibv_cq *cq;
        // 调用`.create_cq`接口创建`cq`
	cq = get_ops(context)->create_cq(context, cqe, channel, comp_vector);
	if (cq)
                // 初始化`cq`
		verbs_init_cq(cq, context, channel, cq_context);
	return cq;
}
```

#### 3.6.1 用户空间`rxe`创建`cq`

`rxe`设置的`.create_cq`接口为`rxe_create_cq`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct ibv_cq *rxe_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct rxe_cq *cq;
	struct urxe_create_cq_resp resp = {};
	int ret;

	cq = calloc(1, sizeof(*cq));
	if (!cq) return NULL;

        // 调用`ibv_cmd_create_cq`创建`cq`
	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->vcq.cq, NULL, 0,
				&resp.ibv_resp, sizeof(resp));
	if (ret) { ... }

        // 映射`cq`的`queue`
	cq->queue = mmap(NULL, resp.mi.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 context->cmd_fd, resp.mi.offset);
	if ((void *)cq->queue == MAP_FAILED) { ... }
        // 计算`cq`的`wc_size`
	cq->wc_size = 1ULL << cq->queue->log2_elem_size;

	if (cq->wc_size < sizeof(struct ib_uverbs_wc)) { ... }
        // 初始化`cq`的`mmap_info`和`lock`
	cq->mmap_info = resp.mi;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	return &cq->vcq.cq;
}
```

`ibv_cmd_create_cq`函数通过`cmd`创建`cq`，实现如下：

```c
// file: rdma-core/libibverbs/cmd_cq.c
int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel, int comp_vector,
		      struct ibv_cq *cq, struct ibv_create_cq *cmd,
		      size_t cmd_size, struct ib_uverbs_create_cq_resp *resp,
		      size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_CQ,
				  UVERBS_METHOD_CQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	return ibv_icmd_create_cq(context, cqe, channel, comp_vector, NULL, 0, cq,
				  cmdb, 0);
}
```

#### 3.6.2 内核空间创建`cq`

`UVERBS_METHOD_CQ_CREATE`对应的内核空间处理函数实现如下：

```c
// file: drivers/infiniband/core/uverbs_std_types_cq.c
static int UVERBS_HANDLER(UVERBS_METHOD_CQ_CREATE)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_ucq_object *obj = container_of(
		uverbs_attr_get_uobject(attrs, UVERBS_ATTR_CREATE_CQ_HANDLE),
		typeof(*obj), uevent.uobject);
	struct ib_uverbs_completion_event_file *ev_file = NULL;
	struct ib_device *ib_dev = attrs->context->device;
	struct ib_umem_dmabuf *umem_dmabuf;
	struct ib_cq_init_attr attr = {};
	struct ib_uobject *ev_file_uobj;
	struct ib_umem *umem = NULL;
        ...

        // 检查`ib_dev`是否支持创建`cq`
	if ((!ib_dev->ops.create_cq && !ib_dev->ops.create_cq_umem) || !ib_dev->ops.destroy_cq)
		return -EOPNOTSUPP;
        // 从用户空间复制`comp_vector`,`cqe`和`user_handle`
	ret = uverbs_copy_from(&attr.comp_vector, attrs, UVERBS_ATTR_CREATE_CQ_COMP_VECTOR);
	if (!ret) ret = uverbs_copy_from(&attr.cqe, attrs, UVERBS_ATTR_CREATE_CQ_CQE);
	if (!ret) ret = uverbs_copy_from(&user_handle, attrs, UVERBS_ATTR_CREATE_CQ_USER_HANDLE);
	if (ret) return ret;
        // 从用户空间复制`flags`
	ret = uverbs_get_flags32(&attr.flags, attrs, UVERBS_ATTR_CREATE_CQ_FLAGS,
				 IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION |
					 IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN);
	if (ret) return ret;

        // 获取`comp_channel`
	ev_file_uobj = uverbs_attr_get_uobject(attrs, UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL);
	if (!IS_ERR(ev_file_uobj)) {
		ev_file = container_of(ev_file_uobj,
				       struct ib_uverbs_completion_event_file, uobj);
		uverbs_uobject_get(ev_file_uobj);
	}
        // 获取`event_file`
	obj->uevent.event_file = ib_uverbs_get_async_event(
		attrs, UVERBS_ATTR_CREATE_CQ_EVENT_FD);
        // 检查`comp_vector`是否合法
	if (attr.comp_vector >= attrs->ufile->device->num_comp_vectors) { ... }

	INIT_LIST_HEAD(&obj->comp_list);
	INIT_LIST_HEAD(&obj->uevent.event_list);

        // 获取`buffer_va`,`buffer_length`
	if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_VA)) {
                ...
                // 获取`umem`
		umem = ib_umem_get(ib_dev, buffer_va, buffer_length, IB_ACCESS_LOCAL_WRITE);
		if (IS_ERR(umem)) { ... }
	} else if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_FD)) {
                ...
                // 获取`umem_dmabuf`
		umem_dmabuf = ib_umem_dmabuf_get_pinned(ib_dev, buffer_offset, buffer_length,
							buffer_fd, IB_ACCESS_LOCAL_WRITE);
		if (IS_ERR(umem_dmabuf)) { ... }
		umem = &umem_dmabuf->umem;
	} else if (uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_OFFSET) ||
		   uverbs_attr_is_valid(attrs, UVERBS_ATTR_CREATE_CQ_BUFFER_LENGTH) ||
		   !ib_dev->ops.create_cq) {
                // 检查`buffer_offset`和`buffer_length`是否合法
		ret = -EINVAL;
		goto err_event_file;
	}
        // 创建`cq`
	cq = rdma_zalloc_drv_obj(ib_dev, ib_cq);
	if (!cq) { ... }

	cq->device        = ib_dev;
	cq->uobject       = obj;
        // 设置`cq`的`comp_handler`和`event_handler`
	cq->comp_handler  = ib_uverbs_comp_handler;
	cq->event_handler = ib_uverbs_cq_event_handler;
	cq->cq_context    = ev_file ? &ev_file->ev_queue : NULL;
	atomic_set(&cq->usecnt, 0);

	rdma_restrack_new(&cq->res, RDMA_RESTRACK_CQ);
	rdma_restrack_set_name(&cq->res, NULL);

        // 调用`.create_cq_umem`或者`.create_cq`创建`cq`
	ret = umem ? ib_dev->ops.create_cq_umem(cq, &attr, umem, attrs) :
		ib_dev->ops.create_cq(cq, &attr, attrs);
	if (ret) goto err_free;

	obj->uevent.uobject.object = cq;
	obj->uevent.uobject.user_handle = user_handle;
	rdma_restrack_add(&cq->res);
	uverbs_finalize_uobj_create(attrs, UVERBS_ATTR_CREATE_CQ_HANDLE);
        // 向用户空间复制`cqe`
	ret = uverbs_copy_to(attrs, UVERBS_ATTR_CREATE_CQ_RESP_CQE, &cq->cqe,
			     sizeof(cq->cqe));
	return ret;
        ...
};
```

#### 3.6.3 用户空间`rxe`创建`cq`

`rxe`设置的`.create_cq`接口为`rxe_create_cq`, 其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static int rxe_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			 struct uverbs_attr_bundle *attrs)
{
	struct ib_udata *udata = &attrs->driver_udata;
	struct ib_device *dev = ibcq->device;
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_create_cq_resp __user *uresp = NULL;
	int err, cleanup_err;

	if (udata) {
                ...
                // 用户空间应答结果
		uresp = udata->outbuf;
	}
	if (attr->flags) { ... }
        // 检查`attr`是否合法
	err = rxe_cq_chk_attr(rxe, NULL, attr->cqe, attr->comp_vector);
	if (err) { ... }
        // 添加`cq`到`cq_pool`
	err = rxe_add_to_pool(&rxe->cq_pool, cq);
	if (err) { ... }
        // 初始化`cq`
	err = rxe_cq_from_init(rxe, cq, attr->cqe, attr->comp_vector, udata, uresp);
	if (err) { ... }
	return 0;
}
```

在创建`cq`后，`rxe`通过`rxe_cq_from_init`初始化`cq`, 实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_cq.c
int rxe_cq_from_init(struct rxe_dev *rxe, struct rxe_cq *cq, int cqe,
		     int comp_vector, struct ib_udata *udata,
		     struct rxe_create_cq_resp __user *uresp)
{
	int err;
	enum queue_type type;

	type = QUEUE_TYPE_TO_CLIENT;
        // 初始化`cq`的`queue`
	cq->queue = rxe_queue_init(rxe, &cqe, sizeof(struct rxe_cqe), type);
	if (!cq->queue) { ... }

        // 映射`cq`的`buf`到用户空间
	err = do_mmap_info(rxe, uresp ? &uresp->mi : NULL, udata,
			   cq->queue->buf, cq->queue->buf_size, &cq->queue->ip);
	if (err) return err;

	cq->is_user = uresp;
	spin_lock_init(&cq->cq_lock);
	cq->ibcq.cqe = cqe;
	return 0;
}
```

可以看到，`cq`中对应的是`struct rxe_cqe`结构，表示任务完成后的返回结果。其定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.h
struct rxe_cqe {
	union {
		struct ib_wc		ibwc;
		struct ib_uverbs_wc	uibwc;
	};
};
```

`rxe_queue_init`函数初始化`rxe_queue`, 分配`buf`, 并返回`num_slots`。

```c
// file: drivers/infiniband/sw/rxe/rxe_queue.c
struct rxe_queue *rxe_queue_init(struct rxe_dev *rxe, int *num_elem,
			unsigned int elem_size, enum queue_type type)
{
	struct rxe_queue *q;
	size_t buf_size;
	unsigned int num_slots;

	/* num_elem == 0 is allowed, but uninteresting */
	if (*num_elem < 0) return NULL;

	q = kzalloc_obj(*q);
	if (!q) return NULL;

	q->rxe = rxe;
	q->type = type;

        // 计算`elem_size`，并取缓存行的整数倍
	q->elem_size = elem_size;
	if (elem_size < cache_line_size())
		elem_size = cache_line_size();
	elem_size = roundup_pow_of_two(elem_size);

	q->log2_elem_size = order_base_2(elem_size);

        // 计算`num_slots`，并取2的幂
	num_slots = *num_elem + 1;
	num_slots = roundup_pow_of_two(num_slots);
	q->index_mask = num_slots - 1;

	buf_size = sizeof(struct rxe_queue_buf) + num_slots * elem_size;
        // 创建`cq`的`buf`
	q->buf = vmalloc_user(buf_size);
	if (!q->buf) goto err2;

	q->buf->log2_elem_size = q->log2_elem_size;
	q->buf->index_mask = q->index_mask;

	q->buf_size = buf_size;
        // 返回`num_slots`
	*num_elem = num_slots - 1;
	return q;
err2:
	kfree(q);
	return NULL;
}
```

### 3.7 创建`qp`

`qp`(Queue Pair)表示一对工作队列，即：`SQ`(Send Queue)和`RQ`(Receive Queue)。SQ和RQ都是WQ(Work Queue)，分别用于发送和接收的请求。其使用如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
	...

	struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
			// 发送队列的通知
			.send_cq = pp_cq(ctx),
			// 接受队列的通知
			.recv_cq = pp_cq(ctx),
			.cap     = {
				// 发送队列和接受队列的长度
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			// 队列类型，设置为RC
			.qp_type = IBV_QPT_RC
		};

		if (use_new_send) {
			struct ibv_qp_init_attr_ex init_attr_ex = {};

			init_attr_ex.send_cq = pp_cq(ctx);
			init_attr_ex.recv_cq = pp_cq(ctx);
			init_attr_ex.cap.max_send_wr = 1;
			init_attr_ex.cap.max_recv_wr = rx_depth;
			init_attr_ex.cap.max_send_sge = 1;
			init_attr_ex.cap.max_recv_sge = 1;
			init_attr_ex.qp_type = IBV_QPT_RC;

			init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_PD |
						  IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
			init_attr_ex.pd = ctx->pd;
			init_attr_ex.send_ops_flags = IBV_QP_EX_WITH_SEND;
			// 创建`qp_ex`
			ctx->qp = ibv_create_qp_ex(ctx->context, &init_attr_ex);
		} else {
			// 创建`qp`
			ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
		}
	...
}
```


`ibv_create_qp`函数用于创建`qp`，调用对应的`.create_qp`接口，实现如下：

```c
// file: rdma-core/libibverbs/verbs.c
LATEST_SYMVER_FUNC(ibv_create_qp, 1_1, "IBVERBS_1.1",
		   struct ibv_qp *,
		   struct ibv_pd *pd,
		   struct ibv_qp_init_attr *qp_init_attr)
{	
	// 调用`.create_qp`接口
	struct ibv_qp *qp = get_ops(pd->context)->create_qp(pd, qp_init_attr);
	return qp;
}
```

#### 3.7.1 用户空间`rxe`创建`qp`

`rxe`设置的`.create_qp`接口为`rxe_create_qp`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static struct ibv_qp *rxe_create_qp(struct ibv_pd *ibpd,
				    struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd = {};
	struct urxe_create_qp_resp resp = {};
	struct rxe_qp *qp;
	int ret;
	// 分配`rxe_qp`
	qp = calloc(1, sizeof(*qp));
	if (!qp) goto err;
        // 调用`ibv_cmd_create_qp`创建`qp`
	ret = ibv_cmd_create_qp(ibpd, &qp->vqp.qp, attr, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret) goto err_free;
	// 内存映射qp
	ret = map_queue_pair(ibpd->context->cmd_fd, qp, attr, &resp.drv_payload);
	if (ret) goto err_destroy;
	// 设置sq的内存映射信息
	qp->sq_mmap_info = resp.sq_mi;
	pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE);

	return &qp->vqp.qp;
	...
}
```

`ibv_cmd_create_qp`函数通过`UVERBS_METHOD_QP_CREATE`命令创建`qp`, 实现如下：

```c
// file: rdma-core/libibverbs/cmd_qp.c
int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ib_uverbs_create_qp_resp *resp, size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_QP,
				  UVERBS_METHOD_QP_CREATE, cmd, cmd_size, resp,
				  resp_size);

	struct ibv_qp_init_attr_ex attr_ex = {};
	int ret;
	// 设置qp初始化属性
	attr_ex.qp_context = attr->qp_context;
	attr_ex.send_cq = attr->send_cq;
	attr_ex.recv_cq = attr->recv_cq;
	attr_ex.srq = attr->srq;
	attr_ex.cap = attr->cap;
	attr_ex.qp_type = attr->qp_type;
	attr_ex.sq_sig_all = attr->sq_sig_all;
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = pd;
	ret = ibv_icmd_create_qp(pd->context, NULL, qp, &attr_ex, cmdb);
	if (!ret)
		// 复制`cap`
		memcpy(&attr->cap, &attr_ex.cap, sizeof(attr_ex.cap));

	return ret;
}
```

#### 3.7.2 内核空间创建`qp`

`UVERBS_METHOD_QP_CREATE`对应的内核空间处理函数实现如下：

```c
// file: drivers/infiniband/core/uverbs_std_types_qp.c
static int UVERBS_HANDLER(UVERBS_METHOD_QP_CREATE)(
	struct uverbs_attr_bundle *attrs)
{
	struct ib_uqp_object *obj = container_of(
		uverbs_attr_get_uobject(attrs, UVERBS_ATTR_CREATE_QP_HANDLE),
		typeof(*obj), uevent.uobject);
	struct ib_qp_init_attr attr = {};
	struct ib_uverbs_qp_cap cap = {};
	...

	ret = uverbs_copy_from_or_zero(&cap, attrs, UVERBS_ATTR_CREATE_QP_CAP);
	if (!ret) ret = uverbs_copy_from(&user_handle, attrs, UVERBS_ATTR_CREATE_QP_USER_HANDLE);
	if (!ret) ret = uverbs_get_const(&attr.qp_type, attrs, UVERBS_ATTR_CREATE_QP_TYPE);
	if (ret) return ret;
	...

	switch (attr.qp_type) {
		...
	case IB_UVERBS_QPT_RC:
	case IB_UVERBS_QPT_UC:
	case IB_UVERBS_QPT_UD:
	case IB_UVERBS_QPT_XRC_INI:
	case IB_UVERBS_QPT_DRIVER:
		...
		// 获取`pd`
		pd = uverbs_attr_get_obj(attrs, UVERBS_ATTR_CREATE_QP_PD_HANDLE);
		if (IS_ERR(pd)) return PTR_ERR(pd);

		rwq_ind_tbl = uverbs_attr_get_obj(attrs, UVERBS_ATTR_CREATE_QP_IND_TABLE_HANDLE);
		if (!IS_ERR(rwq_ind_tbl)) { ... } else {
			// 获取`send_cq`
			send_cq = uverbs_attr_get_obj(attrs, UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE);
			if (IS_ERR(send_cq)) return PTR_ERR(send_cq);
			if (attr.qp_type != IB_QPT_XRC_INI) {
				// 获取`recv_cq`
				recv_cq = uverbs_attr_get_obj(attrs, UVERBS_ATTR_CREATE_QP_RECV_CQ_HANDLE);
				if (IS_ERR(recv_cq)) return PTR_ERR(recv_cq);
			}
		}
		device = pd->device;
		break;
		...
	}
	...
	// 检查`create_flags`
	ret = check_creation_flags(attr.qp_type, attr.create_flags);
	if (ret) return ret;
	...

	// 获取`srq`
	srq = uverbs_attr_get_obj(attrs, UVERBS_ATTR_CREATE_QP_SRQ_HANDLE);
	if (!IS_ERR(srq)) {
		// srq检查
		if ((srq->srq_type == IB_SRQT_XRC && attr.qp_type != IB_QPT_XRC_TGT) ||
		    (srq->srq_type != IB_SRQT_XRC && attr.qp_type == IB_QPT_XRC_TGT))
			return -EINVAL;
		attr.srq = srq;
	}

	obj->uevent.event_file = ib_uverbs_get_async_event(attrs, UVERBS_ATTR_CREATE_QP_EVENT_FD);
	INIT_LIST_HEAD(&obj->uevent.event_list);
	INIT_LIST_HEAD(&obj->mcast_list);
	obj->uevent.uobject.user_handle = user_handle;
	attr.event_handler = ib_uverbs_qp_event_handler;
	attr.send_cq = send_cq;
	attr.recv_cq = recv_cq;
	attr.xrcd = xrcd;
	...

	set_caps(&attr, &cap, true);
	mutex_init(&obj->mcast_lock);

	// 内核空间创建`qp`
	qp = ib_create_qp_user(device, pd, &attr, &attrs->driver_udata, obj, KBUILD_MODNAME);
	if (IS_ERR(qp)) { ... }
	ib_qp_usecnt_inc(qp);

	if (attr.qp_type == IB_QPT_XRC_TGT) { ... }
	obj->uevent.uobject.object = qp;
	uverbs_finalize_uobj_create(attrs, UVERBS_ATTR_CREATE_QP_HANDLE);

	set_caps(&attr, &cap, false);
	ret = uverbs_copy_to_struct_or_zero(attrs, UVERBS_ATTR_CREATE_QP_RESP_CAP, &cap, sizeof(cap));
	if (ret) return ret;

	// 复制`qp_num`到用户空间
	ret = uverbs_copy_to(attrs, UVERBS_ATTR_CREATE_QP_RESP_QP_NUM, &qp->qp_num, sizeof(qp->qp_num));
	return ret;
err_put:
	if (obj->uevent.event_file)
		uverbs_uobject_put(&obj->uevent.event_file->uobj);
	return ret;
};
```

`ib_create_qp_user`函数调用`create_qp`创建`qp`, 如下：

```c
// file: drivers/infiniband/core/verbs.c
struct ib_qp *ib_create_qp_user(struct ib_device *dev, struct ib_pd *pd,
				struct ib_qp_init_attr *attr,
				struct ib_udata *udata,
				struct ib_uqp_object *uobj, const char *caller)
{
	struct ib_qp *qp, *xrc_qp;

	if (attr->qp_type == IB_QPT_XRC_TGT)
		qp = create_qp(dev, pd, attr, NULL, NULL, caller);
	else
		qp = create_qp(dev, pd, attr, udata, uobj, NULL);
	if (attr->qp_type != IB_QPT_XRC_TGT || IS_ERR(qp))
		return qp;
	...
}
```

`create_qp`进行实际的创建工作，如下：

```c
// file: drivers/infiniband/core/verbs.c
static struct ib_qp *create_qp(struct ib_device *dev, struct ib_pd *pd,
			       struct ib_qp_init_attr *attr,
			       struct ib_udata *udata,
			       struct ib_uqp_object *uobj, const char *caller)
{
	struct ib_udata dummy = {};
	struct ib_qp *qp;
	int ret;

	if (!dev->ops.create_qp) return ERR_PTR(-EOPNOTSUPP);
	// 分配内存空间
	qp = rdma_zalloc_drv_obj_numa(dev, ib_qp);
	if (!qp) return ERR_PTR(-ENOMEM);
	// 设置相关属性
	qp->device = dev;
	qp->pd = pd;
	qp->uobject = uobj;
	qp->real_qp = qp;

	qp->qp_type = attr->qp_type;
	qp->rwq_ind_tbl = attr->rwq_ind_tbl;
	qp->srq = attr->srq;
	qp->event_handler = __ib_qp_event_handler;
	qp->registered_event_handler = attr->event_handler;
	qp->port = attr->port_num;
	qp->qp_context = attr->qp_context;

	spin_lock_init(&qp->mr_lock);
	INIT_LIST_HEAD(&qp->rdma_mrs);
	INIT_LIST_HEAD(&qp->sig_mrs);
	init_completion(&qp->srq_completion);
	// 设置`send_cq`和`recv_cq`
	qp->send_cq = attr->send_cq;
	qp->recv_cq = attr->recv_cq;

	rdma_restrack_new(&qp->res, RDMA_RESTRACK_QP);
	WARN_ONCE(!udata && !caller, "Missing kernel QP owner");
	rdma_restrack_set_name(&qp->res, udata ? NULL : caller);
	// 调用`.create_qp`接口
	ret = dev->ops.create_qp(qp, attr, udata);
	if (ret) goto err_create;

	qp->send_cq = attr->send_cq;
	qp->recv_cq = attr->recv_cq;

	ret = ib_create_qp_security(qp, dev);
	if (ret) goto err_security;

	rdma_restrack_add(&qp->res);
	return qp;
	...
}
```

#### 3.7.3 内核空间`rxe`创建`qp`

`rxe`设置的`.create_qp`接口为`rxe_create_qp`, 其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static int rxe_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init,
			 struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_pd *pd = to_rpd(ibqp->pd);
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_create_qp_resp __user *uresp = NULL;
	int err, cleanup_err;

	...
	// 初始化参数检查
	err = rxe_qp_chk_init(rxe, init);
	if (err) { ... }
	// 添加到`qp_pool`
	err = rxe_add_to_pool(&rxe->qp_pool, qp);
	if (err)  { ... }
	// 初始化`qp`
	err = rxe_qp_from_init(rxe, qp, pd, init, uresp, ibqp->pd, udata);
	if (err) { ... }
	rxe_finalize(qp);
	return 0;
	...
}
```

`rxe_qp_from_init`函数进行实际的初始化工作，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
int rxe_qp_from_init(struct rxe_dev *rxe, struct rxe_qp *qp, struct rxe_pd *pd,
		     struct ib_qp_init_attr *init,
		     struct rxe_create_qp_resp __user *uresp,
		     struct ib_pd *ibpd,
		     struct ib_udata *udata)
{
	int err;
	// 获取`rcq`,`scq`和`srq`
	struct rxe_cq *rcq = to_rcq(init->recv_cq);
	struct rxe_cq *scq = to_rcq(init->send_cq);
	struct rxe_srq *srq = init->srq ? to_rsrq(init->srq) : NULL;
	unsigned long flags;

	rxe_get(pd);
	rxe_get(rcq);
	rxe_get(scq);
	if (srq) rxe_get(srq);
	// 设置qp属性
	qp->pd = pd;
	qp->rcq = rcq;
	qp->scq = scq;
	qp->srq = srq;
	atomic_inc(&rcq->num_wq);
	atomic_inc(&scq->num_wq);

	// 设置qp杂项属性，如：mtu,qp_num,req_pkts,resp_pkts等
	rxe_qp_init_misc(rxe, qp, init);
	// 初始化请求设置，即：sq
	err = rxe_qp_init_req(rxe, qp, init, udata, uresp);
	if (err) goto err1;
	// 初始化回复设置，即：rq
	err = rxe_qp_init_resp(rxe, qp, init, udata, uresp);
	if (err) goto err2;

	spin_lock_irqsave(&qp->state_lock, flags);
	qp->attr.qp_state = IB_QPS_RESET;
	qp->valid = 1;
	spin_unlock_irqrestore(&qp->state_lock, flags);
	return 0;
	...
}
```

我们可以看到，`rxe_qp_from_init`分别进行`req`(`sq`)和`resp`(`rq`)的初始化工作，接下来我们继续分析其实现过程。

##### 1. sq的初始化

`rxe_qp_init_req`初始化`rxe`的请求设置，通过请求发送数据。其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
static int rxe_qp_init_req(struct rxe_dev *rxe, struct rxe_qp *qp,
			   struct ib_qp_init_attr *init, struct ib_udata *udata,
			   struct rxe_create_qp_resp __user *uresp)
{
	int err;
	// 初始化`req_pkts`
	skb_queue_head_init(&qp->req_pkts);
	// 创建udp socket
	err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, 0, &qp->sk);
	if (err < 0) return err;
	rxe_reclassify_send_socket(qp->sk);
	qp->sk->sk->sk_user_data = qp;
	// 根据QPN确定UDP的源端口
	qp->src_port = RXE_ROCE_V2_SPORT + (hash_32(qp_num(qp), 14) & 0x3fff);
	// 初始化sq
	err = rxe_init_sq(qp, init, udata, uresp);
	if (err) return err;
	// 确定req队列的起始位置
	qp->req.wqe_index = queue_get_producer(qp->sq.queue, QUEUE_TYPE_FROM_CLIENT);
	// 设置req和comp的操作码无效
	qp->req.opcode		= -1;
	qp->comp.opcode		= -1;
	// 初始化`send_task`
	rxe_init_task(&qp->send_task, qp, rxe_sender);

	qp->qp_timeout_jiffies = 0;
	if (init->qp_type == IB_QPT_RC) {
		// RC类型的qp，设置`nak`和`retrans`定时器，用于检测数据重传
		timer_setup(&qp->rnr_nak_timer, rnr_nak_timer, 0);
		timer_setup(&qp->retrans_timer, retransmit_timer, 0);
	}
	return 0;
}
```

`rxe_init_sq`初始化sq，其工作方式和`cq`类似，通过设置发送队列后映射到用户空间，其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
static int rxe_init_sq(struct rxe_qp *qp, struct ib_qp_init_attr *init,
		       struct ib_udata *udata,
		       struct rxe_create_qp_resp __user *uresp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	int wqe_size;
	int err;
	// 确定队列中wqe的大小和数量
	qp->sq.max_wr = init->cap.max_send_wr;
	wqe_size = max_t(int, init->cap.max_send_sge * sizeof(struct ib_sge),
			 init->cap.max_inline_data);
	qp->sq.max_sge = wqe_size / sizeof(struct ib_sge);
	qp->sq.max_inline = wqe_size;
	wqe_size += sizeof(struct rxe_send_wqe);
	// 初始化sq
	qp->sq.queue = rxe_queue_init(rxe, &qp->sq.max_wr, wqe_size, QUEUE_TYPE_FROM_CLIENT);
	if (!qp->sq.queue) { ... }
	// 映射到用户空间
	err = do_mmap_info(rxe, uresp ? &uresp->sq_mi : NULL, udata,
			   qp->sq.queue->buf, qp->sq.queue->buf_size,
			   &qp->sq.queue->ip);
	if (err) { ... }
	// 返回实际队列的容量
	init->cap.max_send_wr = qp->sq.max_wr;
	init->cap.max_send_sge = qp->sq.max_sge;
	init->cap.max_inline_data = qp->sq.max_inline;
	return 0;
	...
}
```

可以看到`sq`队列中的项为`struct rxe_send_wqe` + n * `struct ib_sge`, 其定义如下：

```c
// file: include/uapi/rdma/rdma_user_rxe.h
struct rxe_send_wqe {
	struct rxe_send_wr	wr;
	__u32			status;
	__u32			state;
	__aligned_u64		iova;
	__u32			mask;
	__u32			first_psn;
	__u32			last_psn;
	__u32			ack_length;
	__u32			ssn;
	__u32			has_rd_atomic;
	struct rxe_dma_info	dma;
};
// file: include/rdma/ib_verbs.h
struct ib_sge {
	u64	addr;
	u32	length;
	u32	lkey;
};
```

##### 2. rq的初始化

`rxe_qp_init_resp`初始化`rxe`的回复设置，通过接收数据进行处理。其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
static int rxe_qp_init_resp(struct rxe_dev *rxe, struct rxe_qp *qp,
			    struct ib_qp_init_attr *init,
			    struct ib_udata *udata,
			    struct rxe_create_qp_resp __user *uresp)
{
	int err;
	// 初始化`resp_pkts`
	skb_queue_head_init(&qp->resp_pkts);

	if (!qp->srq) {
		// 使用`rq`时，初始化`rq`
		err = rxe_init_rq(qp, init, udata, uresp);
		if (err) return err;
	}
	// 初始化`recv_task`
	rxe_init_task(&qp->recv_task, qp, rxe_receiver);
	// 设置resp的状态
	qp->resp.opcode		= OPCODE_NONE;
	qp->resp.msn		= 0;
	return 0;
}
```

在不是使用`srq`，使用单独`rq`的情况下，初始化`rq`，`rxe_init_rq`完成该项工作，实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
static int rxe_init_rq(struct rxe_qp *qp, struct ib_qp_init_attr *init,
		       struct ib_udata *udata,
		       struct rxe_create_qp_resp __user *uresp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	int wqe_size;
	int err;
	// 确定队列中wqe的大小和数量
	qp->rq.max_wr = init->cap.max_recv_wr;
	qp->rq.max_sge = init->cap.max_recv_sge;
	wqe_size = sizeof(struct rxe_recv_wqe) + qp->rq.max_sge*sizeof(struct ib_sge);
	// 初始化rq
	qp->rq.queue = rxe_queue_init(rxe, &qp->rq.max_wr, wqe_size, QUEUE_TYPE_FROM_CLIENT);
	if (!qp->rq.queue) { ... }
	// 映射到用户空间
	err = do_mmap_info(rxe, uresp ? &uresp->rq_mi : NULL, udata,
			   qp->rq.queue->buf, qp->rq.queue->buf_size,
			   &qp->rq.queue->ip);
	if (err) { ... }
	// 返回实际的数量
	init->cap.max_recv_wr = qp->rq.max_wr;
	return 0;
	...
}
```

可以看到`rq`队列中的项`struct rxe_recv_wqe` + n * `struct ib_sge`, 其定义如下：

```c
// file: include/uapi/rdma/rdma_user_rxe.h
struct rxe_recv_wqe {
	__aligned_u64		wr_id;
	__u32			reserved;
	__u32			padding;
	struct rxe_dma_info	dma;
};
// file: include/rdma/ib_verbs.h
struct ib_sge {
	u64	addr;
	u32	length;
	u32	lkey;
};
```

### 3.8 修改`qp`

在上节我们创建了一个`qp`，其状态处于`IB_QPS_RESET`状态，此时我们尚不能使用，需要修改状态才能正常使用。QP的状态定义如下：

```c
// file: include/rdma/ib_verbs.h
enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};
```

主要的状态含义如下：

* RESET: 复位状态。当一个QP通过Create QP创建好之后就处于这个状态，相关的资源都已经申请好了，但是这个QP目前什么都做不了，其无法接收用户下发的WQE，也无法接受对端某个QP的消息。
* INIT（Initialized）: 已初始化状态。这个状态下，用户可以通过Post Receive给这个QP下发Receive WR，但是接收到的消息并不会被处理，会被静默丢弃；如果用户下发了一个Post Send的WR，则会报错。
* RTR（Ready to Receive）: 准备接收状态。在INIT状态的基础上，RQ可以正常工作，即对于接收到的消息，可以按照其中WQE的指示搬移数据到指定内存位置。此状态下SQ仍然不能工作。
* RTS（Ready to Send）: 准备发送状态。在RTR基础上，SQ可以正常工作，即用户可以进行Post Send，并且硬件也会根据SQ的内容将数据发送出去。进入该状态前，QP必须已于对端建立好链接。
* SQD（Send Queue Drain）: SQ排空状态。顾名思义，该状态会将SQ队列中现存的未处理的WQE全部处理掉，这个时候用户还可以下发新的WQE下来，但是这些WQE要等到旧的WQE全处理之后才会被处理。
* SQE（Send Queue Error）: SQ错误状态。当某个Send WR发生完成错误（即硬件通过CQE告知驱动发生的错误）时，会导致QP进入此状态。
* ERR（Error）: 错误状态。其他状态如果发生了错误，都可能进入该状态。Error状态时，QP会停止处理WQE，已经处理到一半的WQE也会停止。上层需要在修复错误后再将QP重新切换到RST的初始状态。

QP常见的状态变更为`RESET → INIT → RTR → RTS`, 用户空间通过`ibv_modify_qp`修改状态，以`IBV_QPS_INIT`为例，使用如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth, int port,
					    int use_event)
{
	...
		// 设置修改属性
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qp_access_flags = 0
		};
		// 修改qp
		if (ibv_modify_qp(ctx->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
}
```

`ibv_modify_qp`的调用`.modify_qp`接口修改`qp`, 其实现如下：

```c
// file: rdma-core/libibverbs/verbs.c
LATEST_SYMVER_FUNC(ibv_modify_qp, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	int ret;
	// 调用`.modify_qp`
	ret = get_ops(qp->context)->modify_qp(qp, attr, attr_mask);
	if (ret) return ret;
	// 修改状态
	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;
	return 0;
}
```

#### 3.8.1 用户空间`rxe`修改`qp`

`rxe`设置的`.modify_qp`接口为`rxe_modify_qp`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int rxe_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	return ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
}
```

`ibv_cmd_modify_qp`通过`IB_USER_VERBS_CMD_MODIFY_QP`命令通知内核修改qp，其实现如下：

```c
// file: rdma-core/libibverbs/cmd.c
int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size)
{
	if (attr_mask & ~(IBV_QP_RATE_LIMIT - 1))
		return EOPNOTSUPP;
	// 复制修改的字段
	copy_modify_qp_fields(qp, attr, attr_mask, &cmd->core_payload);
	// 执行`IB_USER_VERBS_CMD_MODIFY_QP`
	return execute_cmd_write_req(qp->context, IB_USER_VERBS_CMD_MODIFY_QP,
				     cmd, cmd_size);
}
```

#### 3.8.2 内核空间修改`qp`

`IB_USER_VERBS_CMD_MODIFY_QP`对于的处理函数为`ib_uverbs_modify_qp`,如下：

```c
const struct uapi_definition uverbs_def_write_intf[] = {
	...
		DECLARE_UVERBS_WRITE(
			IB_USER_VERBS_CMD_MODIFY_QP,
			ib_uverbs_modify_qp,
			UAPI_DEF_WRITE_I(struct ib_uverbs_modify_qp),
			UAPI_DEF_METHOD_NEEDS_FN(modify_qp)),
	...
};
```

其实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
static int ib_uverbs_modify_qp(struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_ex_modify_qp cmd;
	int ret;
	// 复制用户空间的请求
	ret = uverbs_request(attrs, &cmd.base, sizeof(cmd.base));
	if (ret) return ret;
	// 检测修改的字段
	if (cmd.base.attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;
	// 修改`qp`
	return modify_qp(attrs, &cmd);
}
```

`modify_qp`函数根据设置的属性和字段进行对应的修改，如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
static int modify_qp(struct uverbs_attr_bundle *attrs,
		     struct ib_uverbs_ex_modify_qp *cmd)
{
	struct ib_qp_attr *attr;
	struct ib_qp *qp;
	int ret;
	
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) return -ENOMEM;
	// 获取qp
	qp = uobj_get_obj_read(qp, UVERBS_OBJECT_QP, cmd->base.qp_handle, attrs);
	if (IS_ERR(qp)) { ... }

	...
	// 检查状态
	if ((cmd->base.attr_mask & IB_QP_CUR_STATE &&
	    cmd->base.cur_qp_state > IB_QPS_ERR) ||
	    (cmd->base.attr_mask & IB_QP_STATE &&
	    cmd->base.qp_state > IB_QPS_ERR)) {
		ret = -EINVAL;
		goto release_qp;
	}
	// 按照设置的属性进行修改
	if (cmd->base.attr_mask & IB_QP_STATE)
		attr->qp_state = cmd->base.qp_state;
	if (cmd->base.attr_mask & IB_QP_CUR_STATE)
		attr->cur_qp_state = cmd->base.cur_qp_state;
	if (cmd->base.attr_mask & IB_QP_PATH_MTU)
		attr->path_mtu = cmd->base.path_mtu;
	if (cmd->base.attr_mask & IB_QP_PATH_MIG_STATE)
		attr->path_mig_state = cmd->base.path_mig_state;
	...

	ret = ib_modify_qp_with_udata(qp, attr,
				      modify_qp_mask(qp->qp_type, cmd->base.attr_mask),
				      &attrs->driver_udata);
release_qp:
	rdma_lookup_put_uobject(&qp->uobject->uevent.uobject, UVERBS_LOOKUP_READ);
out:
	kfree(attr);
	return ret;
}
```

### 3.9 接收数据

我们先略过`ibv_query_gid`，`ibv_query_port`等过程，其实现与上面的类似。接下来我们分析接收数据的实现过程。用户空间通过`ibv_post_recv`提交接收数据请求，如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static int pp_post_recv(struct pingpong_context *ctx, int n)
{
        // 接收数据的sge
	struct ibv_sge list = {
		.addr	= use_dm ? 0 : (uintptr_t) ctx->buf,
		.length = ctx->size,
		.lkey	= ctx->mr->lkey
	};
        // 接收数据的wr
	struct ibv_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;
	int i;

	for (i = 0; i < n; ++i)
                // 提交接收数据请求
		if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
			break;

	return i;
}
```

RDMA中使用SGL(Scatter/Gather List)发送/接收数据，SGL是一个数组。该数组中的元素被称之为SGE(Scatter/Gather Element)，每一个SGE就是一个Data Segment(数据段)， 用`struct ibv_sge`表示，其定义如下：

```c
// file: rdma-core/libibverbs/verbs.h
struct ibv_sge {
	uint64_t		addr;
	uint32_t		length;
	uint32_t		lkey;
};
```

`struct ibv_recv_wr`中的`.sg_list`字段表示sgl，实例中使用一个。`ibv_post_recv`调用`.post_recv`接口接收数据。如下:

```c
// file: rdma-core/libibverbs/verbs.h
static inline int ibv_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
				struct ibv_recv_wr **bad_wr)
{
	return qp->context->ops.post_recv(qp, wr, bad_wr);
}
```

#### 3.9.1 用户空间`rxe`提交接收WR

`rxe`设置的`.post_recv`接口为`rxe_post_recv`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int rxe_post_recv(struct ibv_qp *ibqp,
			 struct ibv_recv_wr *recv_wr,
			 struct ibv_recv_wr **bad_wr)
{
	int rc = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_wq *rq = &qp->rq;

        // 检查参数
	if (!bad_wr) return EINVAL;
	*bad_wr = NULL;
	if (!rq || !recv_wr || !rq->queue) return EINVAL;
        // 检查qp状态
	if (ibqp->state == IBV_QPS_RESET) return EINVAL;

	pthread_spin_lock(&rq->lock);
        // 处理recv_wr链表
	while (recv_wr) {
                // 接收一个wr
		rc = rxe_post_one_recv(rq, recv_wr);
		if (rc) {
			*bad_wr = recv_wr;
			break;
		}
		recv_wr = recv_wr->next;
	}
	pthread_spin_unlock(&rq->lock);
	return rc;
}
```

`rxe_post_one_recv`函数实现了接收一个wr的过程。如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int rxe_post_one_recv(struct rxe_wq *rq, struct ibv_recv_wr *recv_wr)
{
	int i;
	struct rxe_recv_wqe *wqe;
	struct rxe_queue_buf *q = rq->queue;
	int num_sge = recv_wr->num_sge;
	int length = 0;
	int rc = 0;
        // 检查队列是否已满
	if (queue_full(q)) { ... }
        // 检查sge数量是否超过最大限制
	if (num_sge > rq->max_sge) { ... }

        // 获取队列生产者地址
	wqe = (struct rxe_recv_wqe *)producer_addr(q);
        // 初始化wqe
	wqe->wr_id = recv_wr->wr_id;
	memcpy(wqe->dma.sge, recv_wr->sg_list, num_sge*sizeof(*wqe->dma.sge));
        // 计算数据长度
	for (i = 0; i < num_sge; i++)
		length += wqe->dma.sge[i].length;
        // 设置dma参数
	wqe->dma.length = length;
	wqe->dma.resid = length;
	wqe->dma.cur_sge = 0;
	wqe->dma.num_sge = num_sge;
	wqe->dma.sge_offset = 0;
        // 增加队列生产者指针
	advance_producer(q);
out:
	return rc;
}
```

### 3.10 发送数据

用户空间通过`ibv_post_send`和`ibv_wr_send`发送数据，我们只分析`ibv_post_send`的实现过程。如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static int pp_post_send(struct pingpong_context *ctx)
{
	// 发送的数据sge
	struct ibv_sge list = {
		.addr	= use_dm ? 0 : (uintptr_t) ctx->buf,
		.length = ctx->size,
		.lkey	= ctx->mr->lkey
	};
	// 发送数据的wr
	struct ibv_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IBV_WR_SEND,
		.send_flags = ctx->send_flags,
	};
	struct ibv_send_wr *bad_wr;

	if (use_new_send) {
		// `ibv_wr_send`方式发送
		ibv_wr_start(ctx->qpx);
		ctx->qpx->wr_id = PINGPONG_SEND_WRID;
		ctx->qpx->wr_flags = ctx->send_flags;
		ibv_wr_send(ctx->qpx);
		ibv_wr_set_sge(ctx->qpx, list.lkey, list.addr, list.length);
		return ibv_wr_complete(ctx->qpx);
	} else {
		// ibv_post_send发送
		return ibv_post_send(ctx->qp, &wr, &bad_wr);
	}
}
```

`struct ibv_send_wr`中的`.sg_list`字段表示sgl，实例中使用一个。`.opcode`表示数据发送的方式，设置为`IBV_WR_SEND`。

`ibv_post_send`调用`.post_send`接口提交发送数据请求。如下:

```c
// file: rdma-core/libibverbs/verbs.h
static inline int ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
				struct ibv_send_wr **bad_wr)
{
	return qp->context->ops.post_send(qp, wr, bad_wr);
}
```

#### 3.10.1 用户空间`rxe`发送数据

`rxe`设置的`.post_send`接口为`rxe_post_send`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int rxe_post_send(struct ibv_qp *ibqp,
			 struct ibv_send_wr *wr_list,
			 struct ibv_send_wr **bad_wr)
{
	int rc = 0;
	int err;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_wq *sq = &qp->sq;

	if (!bad_wr) return EINVAL;
	*bad_wr = NULL;
	if (!sq || !wr_list || !sq->queue) return EINVAL;

	pthread_spin_lock(&sq->lock);
	// 遍历列表
	while (wr_list) {
		// 提交单个发送数据请求
		rc = post_one_send(qp, sq, wr_list);
		if (rc) {
			// 失败时设置`bad_wr`
			*bad_wr = wr_list;
			break;
		}
		wr_list = wr_list->next;
	}
	pthread_spin_unlock(&sq->lock);
	// 发送db(doorbell)
	err =  post_send_db(ibqp);
	return err ? err : rc;
}
```

##### 1. 提交单个发送数据请求

`post_one_send`提交单个发送数据请求，其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int post_one_send(struct rxe_qp *qp, struct rxe_wq *sq,
			 struct ibv_send_wr *ibwr)
{
	int err;
	struct rxe_send_wqe *wqe;
	unsigned int length = 0;
	int i;
	// 计算sgl的长度
	for (i = 0; i < ibwr->num_sge; i++)
		length += ibwr->sg_list[i].length;
	// wr的基本检验
	err = validate_send_wr(qp, ibwr, length);
	if (err) { ...	}

	// 获取发送队列的wqe
	wqe = (struct rxe_send_wqe *)producer_addr(sq->queue);
	// 初始化wqe
	err = init_send_wqe(qp, sq, ibwr, length, wqe);
	if (err) return err;
	// 检查发送队列是否已满
	if (queue_full(sq->queue)) return ENOMEM;
	// 增加生产者计数
	advance_producer(sq->queue);
	rdma_tracepoint(rdma_core_rxe, post_send,
			qp->vqp.qp.context->device->name,
			qp->vqp.qp.qp_num,
			(char *)ibv_wr_opcode_str(ibwr->opcode),
			length);
	return 0;
}
```

`init_send_wqe`函数将`wr`转换为`wqe`，其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int init_send_wqe(struct rxe_qp *qp, struct rxe_wq *sq,
		  struct ibv_send_wr *ibwr, unsigned int length,
		  struct rxe_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	int i;
	unsigned int opcode = ibwr->opcode;
	// 将用户空间的wr转换为内核空间的wr
	convert_send_wr(qp, &wqe->wr, ibwr);
	// UD类型的适应
	if (qp_type(qp) == IBV_QPT_UD) {
		struct rxe_ah *ah = to_rah(ibwr->wr.ud.ah);
		if (!ah->ah_num)
			memcpy(&wqe->wr.wr.ud.av, &ah->av, sizeof(struct rxe_av));
	}

	if (ibwr->send_flags & IBV_SEND_INLINE) {
		// 生成线性数据
		uint8_t *inline_data = wqe->dma.inline_data;
		for (i = 0; i < num_sge; i++) {
			memcpy(inline_data, (uint8_t *)(long)ibwr->sg_list[i].addr,
			       ibwr->sg_list[i].length);
			inline_data += ibwr->sg_list[i].length;
		}
	} else
		// 复制sel
		memcpy(wqe->dma.sge, ibwr->sg_list, num_sge*sizeof(struct ibv_sge));
	// 设置`iova`
	if ((opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
	    || (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD))
		wqe->iova	= ibwr->wr.atomic.remote_addr;
	else
		wqe->iova	= ibwr->wr.rdma.remote_addr;
	// 设置dma
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= 0;
	return 0;
}
```

`convert_send_wr`将用户空间的wr转换为内核空间的wr，其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static void convert_send_wr(struct rxe_qp *qp, struct rxe_send_wr *kwr,
					struct ibv_send_wr *uwr)
{
	struct ibv_mw *ibmw;
	struct ibv_mr *ibmr;

	memset(kwr, 0, sizeof(*kwr));
	// 基本属性
	kwr->wr_id		= uwr->wr_id;
	kwr->opcode		= uwr->opcode;
	kwr->send_flags		= uwr->send_flags;
	kwr->ex.imm_data	= uwr->imm_data;

	switch (uwr->opcode) {
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_READ:
		kwr->wr.rdma.remote_addr	= uwr->wr.rdma.remote_addr;
		kwr->wr.rdma.rkey		= uwr->wr.rdma.rkey;
		break;
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		if (qp_type(qp) == IBV_QPT_UD) {
			struct rxe_ah *ah = to_rah(uwr->wr.ud.ah);
			kwr->wr.ud.remote_qpn	= uwr->wr.ud.remote_qpn;
			kwr->wr.ud.remote_qkey	= uwr->wr.ud.remote_qkey;
			kwr->wr.ud.ah_num	= ah->ah_num;
		}
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		kwr->wr.atomic.remote_addr	= uwr->wr.atomic.remote_addr;
		kwr->wr.atomic.compare_add	= uwr->wr.atomic.compare_add;
		kwr->wr.atomic.swap		= uwr->wr.atomic.swap;
		kwr->wr.atomic.rkey		= uwr->wr.atomic.rkey;
		break;
	case IBV_WR_BIND_MW:
		ibmr = uwr->bind_mw.bind_info.mr;
		ibmw = uwr->bind_mw.mw;
		kwr->wr.mw.addr = uwr->bind_mw.bind_info.addr;
		kwr->wr.mw.length = uwr->bind_mw.bind_info.length;
		kwr->wr.mw.mr_lkey = ibmr->lkey;
		kwr->wr.mw.mw_rkey = ibmw->rkey;
		kwr->wr.mw.rkey = uwr->bind_mw.rkey;
		kwr->wr.mw.access = uwr->bind_mw.bind_info.mw_access_flags;
		break;
	default:
		break;
	}
}
```

##### 2. 发送DB(doorbell)

在逐个将用户空间的发送数据的wr存放到内核空间后，我们需要通知内核空间发送数据，`post_send_db`完成此功能，其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int post_send_db(struct ibv_qp *ibqp)
{
	struct ibv_post_send cmd;
	struct ib_uverbs_post_send_resp resp;

	cmd.hdr.command	= IB_USER_VERBS_CMD_POST_SEND;
	cmd.hdr.in_words = sizeof(cmd) / 4;
	cmd.hdr.out_words = sizeof(resp) / 4;
	cmd.response	= (uintptr_t)&resp;
	cmd.qp_handle	= ibqp->handle;
	cmd.wr_count	= 0;
	cmd.sge_count	= 0;
	cmd.wqe_size	= sizeof(struct ibv_send_wr);

	if (write(ibqp->context->cmd_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
		return errno;
	return 0;
}
```

`post_send_db`通过`IB_USER_VERBS_CMD_POST_SEND`通知内核空间发送数据。

#### 3.10.2 内核空间发送数据

`IB_USER_VERBS_CMD_POST_SEND`对于的处理函数为`ib_uverbs_post_send`,如下：

```c
const struct uapi_definition uverbs_def_write_intf[] = {
	...
		DECLARE_UVERBS_WRITE(
			IB_USER_VERBS_CMD_POST_SEND,
			ib_uverbs_post_send,
			UAPI_DEF_WRITE_IO(struct ib_uverbs_post_send,
					  struct ib_uverbs_post_send_resp),
			UAPI_DEF_METHOD_NEEDS_FN(post_send)),
	...
};
```

其实现如下：

```c
// file: drivers/infiniband/core/uverbs_cmd.c
static int ib_uverbs_post_send(struct uverbs_attr_bundle *attrs)
{
	struct ib_uverbs_post_send      cmd;
	struct ib_uverbs_post_send_resp resp;
	struct ib_uverbs_send_wr       *user_wr;
	struct ib_send_wr              *wr = NULL, *last, *next;
	...

	// 获取用户空间的wqes,sgls
	ret = uverbs_request_start(attrs, &iter, &cmd, sizeof(cmd));
	if (ret) return ret;
	wqes = uverbs_request_next_ptr(&iter, size_mul(cmd.wqe_size, cmd.wr_count));
	if (IS_ERR(wqes)) return PTR_ERR(wqes);
	sgls = uverbs_request_next_ptr(&iter, size_mul(cmd.sge_count, sizeof(struct ib_uverbs_sge)));
	if (IS_ERR(sgls)) return PTR_ERR(sgls);
	ret = uverbs_request_finish(&iter);
	if (ret) return ret;

	// 分配内核空间的wr
	user_wr = kmalloc(cmd.wqe_size, GFP_KERNEL);
	if (!user_wr) return -ENOMEM;

	// 获取qp
	qp = uobj_get_obj_read(qp, UVERBS_OBJECT_QP, cmd.qp_handle, attrs);
	if (IS_ERR(qp)) { ... }

	is_ud = qp->qp_type == IB_QPT_UD;
	sg_ind = 0;
	last = NULL;
	for (i = 0; i < cmd.wr_count; ++i) {
		// 将用户空间的wr转换为内核空间的wr
		...
	}

	resp.bad_wr = 0;
	// `.post_send`接口发送数据
	ret = qp->device->ops.post_send(qp->real_qp, wr, &bad_wr);
	if (ret)
		// 失败时记录`bad_wr`
		for (next = wr; next; next = next->next) {
			++resp.bad_wr;
			if (next == bad_wr) break;
		}
	// 生成应答
	ret2 = uverbs_response(attrs, &resp, sizeof(resp));
	if (ret2) ret = ret2;

out_put:
	rdma_lookup_put_uobject(&qp->uobject->uevent.uobject, UVERBS_LOOKUP_READ);

	while (wr) {
		if (is_ud && ud_wr(wr)->ah) uobj_put_obj_read(ud_wr(wr)->ah);
		next = wr->next;
		kfree(wr);
		wr = next;
	}
out:
	kfree(user_wr);
	return ret;
}
```

#### 3.10.3 内核空间`rxe`发送数据

`rxe`设置的`.post_send`接口为`rxe_post_send`, 其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_verbs.c
static int rxe_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	struct rxe_qp *qp = to_rqp(ibqp);
	int err;
	unsigned long flags;
	...

	if (qp->is_user) {
		// 启动`send_task`
		rxe_sched_task(&qp->send_task);
	} else {
		err = rxe_post_send_kernel(qp, wr, bad_wr);
		if (err) return err;
	}
	return 0;
}
```

`rxe_sched_task`调度任务执行，`send_task`设置的执行接口为`rxe_sender`, 其实现如下:

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
int rxe_sender(struct rxe_qp *qp)
{
	int req_ret;
	int comp_ret;
	// 处理发送队列
	req_ret = rxe_requester(qp);
	// 处理应答队列
	comp_ret = rxe_completer(qp);

	return (req_ret && comp_ret) ? -EAGAIN : 0;
}
```

### 3.11 内核收发数据的实现

#### 3.11.1 发送数据的过程

上一节中，`rxe_post_send`函数将用户空间的wr转换为内核空间的wr后，调用`rxe_requester`发送数据。`rxe_requester`函数是数据发送的处理接口，从发送队列中获取wqe后，生成skb后发送，其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_req.c
int rxe_requester(struct rxe_qp *qp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_pkt_info pkt;
	struct sk_buff *skb;
	struct rxe_send_wqe *wqe;
	...
	// 发送队列
	struct rxe_queue *q = qp->sq.queue;
	struct rxe_ah *ah;
	struct rxe_av *av;
	unsigned long flags;

	...
	// 检查qp是否需要重传
	if (unlikely(qp->req.need_retry && !qp->req.wait_for_rnr_timer)) {
		req_retry(qp);
		qp->req.need_retry = 0;
	}
	// 获取下一个wqe
	wqe = req_next_wqe(qp);
	if (unlikely(!wqe)) goto exit;

	// 检查wqe是否需要等待
	if (rxe_wqe_is_fenced(qp, wqe)) {
		qp->req.wait_fence = 1;
		goto exit;
	}
	// `IB_WR_LOCAL_INV`,`IB_WR_REG_MR`,`IB_WR_BIND_MW`等本地操作
	if (wqe->mask & WR_LOCAL_OP_MASK) {
		err = rxe_do_local_ops(qp, wqe);
		if (unlikely(err)) goto err; else goto done;
	}
	// RC检查是否需要等待psn
	if (unlikely(qp_type(qp) == IB_QPT_RC &&
		psn_compare(qp->req.psn, (qp->comp.psn + RXE_MAX_UNACKED_PSNS)) > 0)) {
		qp->req.wait_psn = 1;
		goto exit;
	}
	// 限制每个QP的正在处理的SKB数量，最多64个
	if (unlikely(atomic_read(&qp->skb_out) > RXE_INFLIGHT_SKBS_PER_QP_HIGH)) {
		qp->need_req_skb = 1;
		goto exit;
	}
	// 获取下一个`opcode`
	opcode = next_opcode(qp, wqe, wqe->wr.opcode);
	if (unlikely(opcode < 0)) { wqe->status = IB_WC_LOC_QP_OP_ERR; goto err; }

	mask = rxe_opcode[opcode].mask;
	if (unlikely(mask & (RXE_READ_OR_ATOMIC_MASK | RXE_ATOMIC_WRITE_MASK))) {
		if (check_init_depth(qp, wqe)) goto exit;
	}
	// 获取mtu和payload
	mtu = get_mtu(qp);
	payload = (mask & (RXE_WRITE_OR_SEND_MASK | RXE_ATOMIC_WRITE_MASK)) ?
			wqe->dma.resid : 0;
	// payload超过mtu时的处理
	if (payload > mtu) {
		if (qp_type(qp) == IB_QPT_UD) { ...  }
		payload = mtu;
	}
	// 设置pktinfo
	pkt.rxe = rxe;
	pkt.opcode = opcode;
	pkt.qp = qp;
	pkt.psn = qp->req.psn;
	pkt.mask = rxe_opcode[opcode].mask;
	pkt.wqe = wqe;

	// 获取地址信息
	av = rxe_get_av(&pkt, &ah);
	if (unlikely(!av)) { ...  }

	// 初始化请求的skb
	skb = init_req_packet(qp, av, wqe, opcode, payload, &pkt);
	if (unlikely(!skb)) { ...  }

	// 完成skb的设置
	err = finish_packet(qp, av, wqe, &pkt, skb, payload);
	if (unlikely(err)) { ...  }
	if (ah) rxe_put(ah);

	// 发送skb
	err = rxe_xmit_packet(qp, &pkt, skb);
	if (err) { ...  }

	// 更新wqe的状态
	update_wqe_state(qp, wqe, &pkt);
	// 更新wqe的psn
	update_wqe_psn(qp, wqe, &pkt, payload);
	// 更新qp请求状态
	update_state(qp, &pkt);

done:
	ret = 0;
	goto out;
err:
	// 错误处理
	qp->req.wqe_index = queue_next_index(qp->sq.queue, qp->req.wqe_index);
	wqe->state = wqe_state_error;
	rxe_qp_error(qp);
exit:
	ret = -EAGAIN;
out:
	return ret;
}
```

`rxe_opcode`记录rxe操作对应的设置信息，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_opcode.c
struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE] = {
	[IB_OPCODE_RC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RC_SEND_FIRST",
		.mask	= RXE_PAYLOAD_MASK | RXE_REQ_MASK | RXE_RWR_MASK |
			  RXE_SEND_MASK | RXE_START_MASK,
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	...
};
```

通过`rxe_opcode`，我们知道skb需要填充哪些内容。

##### 1. 网络地址的设置

`struct rxe_av`记录qp的路由、源地址、目的地址信息，其定义如下：

```c
// file: include/uapi/rdma/rdma_user_rxe.h
struct rxe_global_route {
	union rxe_gid	dgid;
	__u32		flow_label;
	__u8		sgid_index;
	__u8		hop_limit;
	__u8		traffic_class;
};
struct rxe_av {
	__u8			port_num;
	/* From RXE_NETWORK_TYPE_* */
	__u8			network_type;
	__u8			dmac[6];
	struct rxe_global_route	grh;
	union {
		struct sockaddr_in	_sockaddr_in;
		struct sockaddr_in6	_sockaddr_in6;
	} sgid_addr, dgid_addr;
};
```

用户空间在修改qp状态为`PTR`时设置的，如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
			  enum ibv_mtu mtu, int sl,
			  struct pingpong_dest *dest, int sgid_idx)
{
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	if (dest->gid.global.interface_id) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = dest->gid;
		attr.ah_attr.grh.sgid_index = sgid_idx;
	}
	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return 1;
	}
	...
}
```

##### 2. 设置SKB数据

`rxe`通过UDP协议实现RDMA通信，`init_req_packet`生成skb，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_req.c
static struct sk_buff *init_req_packet(struct rxe_qp *qp,
				       struct rxe_av *av,
				       struct rxe_send_wqe *wqe,
				       int opcode, u32 payload,
				       struct rxe_pkt_info *pkt)
{
	struct rxe_dev		*rxe = to_rdev(qp->ibqp.device);
	struct sk_buff		*skb;
	struct rxe_send_wr	*ibwr = &wqe->wr;
	int			pad = (-payload) & 0x3;
	int			paylen;
	int			solicited;
	u32			qp_num;
	int			ack_req = 0;

	// 计算skb的长度
	paylen = rxe_opcode[opcode].length + payload + pad + RXE_ICRC_SIZE;
	pkt->paylen = paylen;

	// 初始化skb
	skb = rxe_init_packet(rxe, av, paylen, pkt);
	if (unlikely(!skb)) return NULL;

	// 初始化bth
	solicited = (ibwr->send_flags & IB_SEND_SOLICITED) &&
			(pkt->mask & RXE_END_MASK) &&
			((pkt->mask & (RXE_SEND_MASK)) ||
			(pkt->mask & (RXE_WRITE_MASK | RXE_IMMDT_MASK)) ==
			(RXE_WRITE_MASK | RXE_IMMDT_MASK));
	// 获取qp_num
	qp_num = (pkt->mask & RXE_DETH_MASK) ? ibwr->wr.ud.remote_qpn : qp->attr.dest_qp_num;

	// 检查是否需要确认
	if (qp_type(qp) != IB_QPT_UD && qp_type(qp) != IB_QPT_UC)
		ack_req = ((pkt->mask & RXE_END_MASK) ||
			   (qp->req.noack_pkts++ > RXE_MAX_PKT_PER_ACK));
	if (ack_req) qp->req.noack_pkts = 0;

	// 初始化bth（Base Transport Header）
	bth_init(pkt, pkt->opcode, solicited, 0, pad, IB_DEFAULT_PKEY_FULL, qp_num, ack_req, pkt->psn);

	// 初始化可选头部
	if (pkt->mask & RXE_RETH_MASK) {
		if (pkt->mask & RXE_FETH_MASK)
			reth_set_rkey(pkt, ibwr->wr.flush.rkey);
		else
			reth_set_rkey(pkt, ibwr->wr.rdma.rkey);
		reth_set_va(pkt, wqe->iova);
		reth_set_len(pkt, wqe->dma.resid);
	}
	// 填空扩展传输头
	if (pkt->mask & RXE_FETH_MASK)
		feth_init(pkt, ibwr->wr.flush.type, ibwr->wr.flush.level);
	if (pkt->mask & RXE_IMMDT_MASK)
		immdt_set_imm(pkt, ibwr->ex.imm_data);
	if (pkt->mask & RXE_IETH_MASK)
		ieth_set_rkey(pkt, ibwr->ex.invalidate_rkey);
	if (pkt->mask & RXE_ATMETH_MASK) {
		atmeth_set_va(pkt, wqe->iova);
		if (opcode == IB_OPCODE_RC_COMPARE_SWAP) {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.swap);
			atmeth_set_comp(pkt, ibwr->wr.atomic.compare_add);
		} else {
			atmeth_set_swap_add(pkt, ibwr->wr.atomic.compare_add);
		}
		atmeth_set_rkey(pkt, ibwr->wr.atomic.rkey);
	}
	if (pkt->mask & RXE_DETH_MASK) {
		if (qp->ibqp.qp_num == 1)
			deth_set_qkey(pkt, GSI_QKEY);
		else
			deth_set_qkey(pkt, ibwr->wr.ud.remote_qkey);
		deth_set_sqp(pkt, qp->ibqp.qp_num);
	}
	return skb;
}
```

`rxe_init_packet`函数分配skb，并进行基本的初始化设置，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
struct sk_buff *rxe_init_packet(struct rxe_dev *rxe, struct rxe_av *av,
				int paylen, struct rxe_pkt_info *pkt)
{
	unsigned int hdr_len;
	struct sk_buff *skb = NULL;
	struct net_device *ndev;
	const struct ib_gid_attr *attr;
	const int port_num = 1;
	// 获取gid_attr
	attr = rdma_get_gid_attr(&rxe->ib_dev, port_num, av->grh.sgid_index);
	if (IS_ERR(attr)) return NULL;

	// 计算L3+L4的长度
	if (av->network_type == RXE_NETWORK_TYPE_IPV4)
		hdr_len = ETH_HLEN + sizeof(struct udphdr) + sizeof(struct iphdr);
	else
		hdr_len = ETH_HLEN + sizeof(struct udphdr) + sizeof(struct ipv6hdr);

	rcu_read_lock();
	// 获取`net_device`
	ndev = rdma_read_gid_attr_ndev_rcu(attr);
	if (IS_ERR(ndev)) { ... }

	// 分配skb
	skb = alloc_skb(paylen + hdr_len + LL_RESERVED_SPACE(ndev), GFP_ATOMIC);
	if (unlikely(!skb)) { ... }

	// 设置时间戳
	skb->tstamp = ktime_get();
	skb_reserve(skb, hdr_len + LL_RESERVED_SPACE(ndev));
	skb->dev	= ndev;
	rcu_read_unlock();
	// 设置L3协议类型
	if (av->network_type == RXE_NETWORK_TYPE_IPV4)
		skb->protocol = htons(ETH_P_IP);
	else
		skb->protocol = htons(ETH_P_IPV6);

	pkt->rxe	= rxe;
	pkt->port_num	= port_num;
	// 获取头部地址
	pkt->hdr	= skb_put(skb, paylen);
	pkt->mask	|= RXE_GRH_MASK;
out:
	rdma_put_gid_attr(attr);
	return skb;
}
```

`rxe`头部信息包括基础头部（bth）和扩展头部，基础头部使用`struct rxe_bth`表示，其定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_hdr.h
struct rxe_bth {
	u8			opcode;
	u8			flags;
	__be16			pkey;
	__be32			qpn;
	__be32			apsn;
};
```

`bth_init`函数实现基础头部的初始化，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_hdr.h
static inline void bth_init(struct rxe_pkt_info *pkt, u8 opcode, int se,
			    int mig, int pad, u16 pkey, u32 qpn, int ack_req,
			    u32 psn)
{
	struct rxe_bth *bth = (struct rxe_bth *)(pkt->hdr);

	bth->opcode = opcode;
	bth->flags = (pad << 4) & BTH_PAD_MASK;
	if (se) bth->flags |= BTH_SE_MASK;
	if (mig) bth->flags |= BTH_MIG_MASK;
	bth->pkey = cpu_to_be16(pkey);
	bth->qpn = cpu_to_be32(qpn & BTH_QPN_MASK);
	psn &= BTH_PSN_MASK;
	if (ack_req) psn |= BTH_ACK_MASK;
	bth->apsn = cpu_to_be32(psn);
}
```

扩展头部包括`RXE_LRH`等，定义如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_opcode.h
enum rxe_hdr_type {
	RXE_LRH,
	RXE_GRH,
	RXE_BTH,
	RXE_RETH,
	RXE_AETH,
	RXE_ATMETH,
	RXE_ATMACK,
	RXE_IETH,
	RXE_RDETH,
	RXE_DETH,
	RXE_IMMDT,
	RXE_FETH,
	RXE_PAYLOAD,
	NUM_HDR_TYPES
};
```

我们以`reth_set_rkey`为例，其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_hdr.h
static inline void __reth_set_rkey(void *arg, u32 rkey)
{
	struct rxe_reth *reth = arg;
	reth->rkey = cpu_to_be32(rkey);
}
static inline void reth_set_rkey(struct rxe_pkt_info *pkt, u32 rkey)
{
	__reth_set_rkey(pkt->hdr + rxe_opcode[pkt->opcode].offset[RXE_RETH], rkey);
}
```

##### 3. 设置skb的L3和L4信息

`finish_packet`完成skb的设置，设置skb的L3和L4信息，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_req.c
static int finish_packet(struct rxe_qp *qp, struct rxe_av *av,
			 struct rxe_send_wqe *wqe, struct rxe_pkt_info *pkt,
			 struct sk_buff *skb, u32 payload)
{
	int err;
        // 准备skb的L3和L4信息
	err = rxe_prepare(av, pkt, skb);
	if (err) return err;

	if (pkt->mask & RXE_WRITE_OR_SEND_MASK) {
                // 处理内联数据
		if (wqe->wr.send_flags & IB_SEND_INLINE) {
			u8 *tmp = &wqe->dma.inline_data[wqe->dma.sge_offset];
			memcpy(payload_addr(pkt), tmp, payload);
			wqe->dma.resid -= payload;
			wqe->dma.sge_offset += payload;
		} else {
                        // 复制数据到skb
			err = copy_data(qp->pd, 0, &wqe->dma,
					payload_addr(pkt), payload,
					RXE_FROM_MR_OBJ);
			if (err) return err;
		}
		if (bth_pad(pkt)) {
                        // 填充L3+L4头部
			u8 *pad = payload_addr(pkt) + payload;
			memset(pad, 0, bth_pad(pkt));
		}
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		/* oA19-2: shall have no payload. */
		wqe->dma.resid = 0;
	}

	if (pkt->mask & RXE_ATOMIC_WRITE_MASK) {
		memcpy(payload_addr(pkt), wqe->dma.atomic_wr, payload);
		wqe->dma.resid -= payload;
	}
	return 0;
}
```

`rxe_prepare`完成skb的L3和L4信息的设置，如下：

```c
// file： drivers/infiniband/sw/rxe/rxe_net.c
int rxe_prepare(struct rxe_av *av, struct rxe_pkt_info *pkt,
		struct sk_buff *skb)
{
	int err = 0;

	if (skb->protocol == htons(ETH_P_IP))
                // 处理IPv4
		err = prepare4(av, pkt, skb);
	else if (skb->protocol == htons(ETH_P_IPV6))
                // 处理IPv6
		err = prepare6(av, pkt, skb);
        // 设置回环包
	if (ether_addr_equal(skb->dev->dev_addr, av->dmac))
		pkt->mask |= RXE_LOOPBACK_MASK;
	return err;
}
```

我们以`prepare6`为例，其实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static int prepare6(struct rxe_av *av, struct rxe_pkt_info *pkt,
		    struct sk_buff *skb)
{
	struct rxe_qp *qp = pkt->qp;
	struct dst_entry *dst;
	struct in6_addr *saddr = &av->sgid_addr._sockaddr_in6.sin6_addr;
	struct in6_addr *daddr = &av->dgid_addr._sockaddr_in6.sin6_addr;
        // 查找路由
	dst = rxe_find_route(skb->dev, qp, av);
	if (!dst) { ...	}
        // 准备UDP头部
	prepare_udp_hdr(skb, cpu_to_be16(qp->src_port), cpu_to_be16(ROCE_V2_UDP_DPORT));
        // 准备IPv6头部
	prepare_ipv6_hdr(dst, skb, saddr, daddr, IPPROTO_UDP,
			 av->grh.traffic_class, av->grh.hop_limit);
        // 释放路由
	dst_release(dst);
	return 0;
}
```

可以看到，skb的UDP目的端口为`ROCE_V2_UDP_DPORT`，即`4791`。

```c
// file: include/rdma/ib_verbs.h
#define ROCE_V2_UDP_DPORT      4791
```

##### 4. 发送skb

`rxe_xmit_packet`完成skb的发送，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
int rxe_xmit_packet(struct rxe_qp *qp, struct rxe_pkt_info *pkt,
		    struct sk_buff *skb)
{
	int err;
	int is_request = pkt->mask & RXE_REQ_MASK;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	unsigned long flags;

	spin_lock_irqsave(&qp->state_lock, flags);
	if ((is_request && (qp_state(qp) < IB_QPS_RTS)) ||
	    (!is_request && (qp_state(qp) < IB_QPS_RTR))) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		rxe_dbg_qp(qp, "Packet dropped. QP is not in ready state\n");
		goto drop;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);
        // 计算CRC
	rxe_icrc_generate(skb, pkt);

	if (pkt->mask & RXE_LOOPBACK_MASK)
                // 本地回环
		err = rxe_loopback(skb, pkt);
	else 
                // 发送skb
		err = rxe_send(skb, pkt);
	if (err) {
		rxe_counter_inc(rxe, RXE_CNT_SEND_ERR);
		return err;
	}
	rxe_counter_inc(rxe, RXE_CNT_SENT_PKTS);
	goto done;
drop:
	kfree_skb(skb);
	err = 0;
done:
	return err;
}
```

`rxe_loopback`完成skb的本地回环，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static int rxe_loopback(struct sk_buff *skb, struct rxe_pkt_info *pkt)
{
	struct sock *sk = pkt->qp->sk->sk;
        // 复制pkt到skb
	memcpy(SKB_TO_PKT(skb), pkt, sizeof(*pkt));

	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = rxe_skb_tx_dtor;
	rxe_get(pkt->qp);
	atomic_inc(&pkt->qp->skb_out);
        // 移除L3头部
	if (skb->protocol == htons(ETH_P_IP))
		skb_pull(skb, sizeof(struct iphdr));
	else
		skb_pull(skb, sizeof(struct ipv6hdr));
        // 获取ib设备
	if (WARN_ON(!ib_device_try_get(&pkt->rxe->ib_dev))) {
		kfree_skb(skb);
		return -EIO;
	}
        // 移除L4头部
	skb_pull(skb, sizeof(struct udphdr));
        // 处理skb
	rxe_rcv(skb);
	return 0;
}
```

`rxe_send`完成skb的发送，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static int rxe_send(struct sk_buff *skb, struct rxe_pkt_info *pkt)
{
	int err;
	struct sock *sk = pkt->qp->sk->sk;

	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = rxe_skb_tx_dtor;
	rxe_get(pkt->qp);
	atomic_inc(&pkt->qp->skb_out);

	if (skb->protocol == htons(ETH_P_IP))
                // ipv4发送
		err = ip_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
	else
                // ipv6发送
		err = ip6_local_out(dev_net(skb_dst(skb)->dev), skb->sk, skb);
	return err;
}
```

#### 3.11.2 接收数据的过程

##### 1. UDP socket的设置

`rxe`通过UDP协议实现RDMA通信，监听UDP端口`4791`，在加载模块时初始化，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe.c
static int __init rxe_module_init(void)
{
        ...
	err = rxe_net_init();
        ...
	return 0;
}
```

`rxe_net_init`创建UDP socket，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
int rxe_net_init(void)
{
	int err;
	recv_sockets.sk6 = NULL;
        // 创建IPv4 socket
	err = rxe_net_ipv4_init();
	if (err) return err;
        // 创建IPv6 socket
	err = rxe_net_ipv6_init();
	if (err) goto err_out;
	err = register_netdevice_notifier(&rxe_net_notifier);
	if (err) { ... }
	return 0;
err_out:
	rxe_net_exit();
	return err;
}
```

`rxe_net_ipv4_init`和`rxe_net_ipv6_init`分别创建IPv4和IPv6 socket，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static int rxe_net_ipv4_init(void)
{
	recv_sockets.sk4 = rxe_setup_udp_tunnel(&init_net, htons(ROCE_V2_UDP_DPORT), false);
	if (IS_ERR(recv_sockets.sk4)) { ... }
	return 0;
}
static int rxe_net_ipv6_init(void)
{
#if IS_ENABLED(CONFIG_IPV6)
	recv_sockets.sk6 = rxe_setup_udp_tunnel(&init_net, htons(ROCE_V2_UDP_DPORT), true);
	if (PTR_ERR(recv_sockets.sk6) == -EAFNOSUPPORT) { ... }
	if (IS_ERR(recv_sockets.sk6)) { ... }
#endif
	return 0;
}
```

`rxe_setup_udp_tunnel`完成UDP socket的创建和设置，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static struct socket *rxe_setup_udp_tunnel(struct net *net, __be16 port, bool ipv6)
{
	int err;
	struct socket *sock;
	struct udp_port_cfg udp_cfg = { };
	struct udp_tunnel_sock_cfg tnl_cfg = { };

	if (ipv6) {
		udp_cfg.family = AF_INET6;
		udp_cfg.ipv6_v6only = 1;
	} else {
		udp_cfg.family = AF_INET;
	}
	udp_cfg.local_udp_port = port;
        // 创建UDP socket
	err = udp_sock_create(net, &udp_cfg, &sock);
	if (err < 0) return ERR_PTR(err);
	rxe_reclassify_recv_socket(sock);
        // 设置UDP隧道参数
	tnl_cfg.encap_type = 1;
	tnl_cfg.encap_rcv = rxe_udp_encap_recv;
        // 设置UDP隧道
	setup_udp_tunnel_sock(net, sock, &tnl_cfg);
	return sock;
}
```

##### 2. UDP隧道接收skb

UDP在接收目的端口为`4791`的skb后，调用`rxe_udp_encap_recv`处理skb，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_net.c
static int rxe_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct udphdr *udph;
	struct rxe_dev *rxe;
	struct net_device *ndev = skb->dev;
        // 获取pkt信息
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

        // 获取rxe设备
	rxe = rxe_get_dev_from_net(ndev);
	if (!rxe && is_vlan_dev(ndev))
		rxe = rxe_get_dev_from_net(vlan_dev_real_dev(ndev));
	if (!rxe) goto drop;

	if (skb_linearize(skb)) {
		ib_device_put(&rxe->ib_dev);
		goto drop;
	}
        // 获取UDP头部
	udph = udp_hdr(skb);
        // 设置pkt信息
	pkt->rxe = rxe;
	pkt->port_num = 1;
	pkt->hdr = (u8 *)(udph + 1);
	pkt->mask = RXE_GRH_MASK;
	pkt->paylen = be16_to_cpu(udph->len) - sizeof(*udph);

        // 移除UDP头部
	skb_pull(skb, sizeof(struct udphdr));
        // 处理skb
	rxe_rcv(skb);
	return 0;
drop:
	kfree_skb(skb);
	return 0;
}
```

* `rxe`处理接收skb

`rxe_rcv`函数处理接收的skb，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_recv.c
void rxe_rcv(struct sk_buff *skb)
{
	int err;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_dev *rxe = pkt->rxe;
        // 检查skb长度是否足够
	if (unlikely(skb->len < RXE_BTH_BYTES)) goto drop;
        // 检查目的地址
	if (rxe_chk_dgid(rxe, skb) < 0) goto drop;

        // 获取BTH操作码和PSN
	pkt->opcode = bth_opcode(pkt);
	pkt->psn = bth_psn(pkt);
	pkt->qp = NULL;
	pkt->mask |= rxe_opcode[pkt->opcode].mask;

	if (unlikely(skb->len < header_size(pkt))) goto drop;
        // 检查头部是否有效
	err = hdr_check(pkt);
	if (unlikely(err)) goto drop;

        // 检查ICRC是否有效
	err = rxe_icrc_check(skb, pkt);
	if (unlikely(err)) goto drop;

	rxe_counter_inc(rxe, RXE_CNT_RCVD_PKTS);
	if (unlikely(bth_qpn(pkt) == IB_MULTICAST_QPN))
                // 处理多播包
		rxe_rcv_mcast_pkt(rxe, skb);
	else
                // 处理单播包
		rxe_rcv_pkt(pkt, skb);
	return;

drop:
	if (pkt->qp) rxe_put(pkt->qp);
	kfree_skb(skb);
	ib_device_put(&rxe->ib_dev);
}
```

我们以单播包为例，分析接收skb的过程。`rxe_rcv_pkt`函数处理单播包，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_recv.c
static inline void rxe_rcv_pkt(struct rxe_pkt_info *pkt, struct sk_buff *skb)
{
	if (pkt->mask & RXE_REQ_MASK)
		rxe_resp_queue_pkt(pkt->qp, skb);
	else
		rxe_comp_queue_pkt(pkt->qp, skb);
}
```

`rxe_resp_queue_pkt`函数将skb加入请求队列，并唤醒接收任务，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
void rxe_resp_queue_pkt(struct rxe_qp *qp, struct sk_buff *skb)
{
	skb_queue_tail(&qp->req_pkts, skb);
	rxe_sched_task(&qp->recv_task);
}
```

`rxe_comp_queue_pkt`函数将skb加入应答队列，并唤醒发送任务，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
void rxe_comp_queue_pkt(struct rxe_qp *qp, struct sk_buff *skb)
{
	rxe_counter_inc(SKB_TO_PKT(skb)->rxe, RXE_CNT_SENDER_SCHED);
	skb_queue_tail(&qp->resp_pkts, skb);
	rxe_sched_task(&qp->send_task);
}
```

#### 3.11.3 `req_pkt`的处理过程

`pkt`有`RXE_REQ_MASK`标记，说明是请求包，需要加入请求队列。`rxe_resp_queue_pkt`函数将skb加入请求队列，并唤醒接收任务。`recv_task`设置的处理接口为`rxe_receiver`, 实现如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
int rxe_receiver(struct rxe_qp *qp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	enum resp_states state;
	struct rxe_pkt_info *pkt = NULL;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&qp->state_lock, flags);
        // 检查QP是否有效
	if (!qp->valid || qp_state(qp) == IB_QPS_ERR ||
			  qp_state(qp) == IB_QPS_RESET) {
		bool notify = qp->valid && (qp_state(qp) == IB_QPS_ERR);
		drain_req_pkts(qp);
		flush_recv_queue(qp, notify);
		spin_unlock_irqrestore(&qp->state_lock, flags);
		goto exit;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;
        // 初始化状态机
	state = RESPST_GET_REQ;
	while (1) {
		rxe_dbg_qp(qp, "state = %s\n", resp_state_name[state]);
		switch (state) {
		case RESPST_GET_REQ:
			state = get_req(qp, &pkt);
			break;
		case RESPST_CHK_PSN:
			state = check_psn(qp, pkt);
			break;
		case RESPST_CHK_OP_SEQ:
			state = check_op_seq(qp, pkt);
			break;
		case RESPST_CHK_OP_VALID:
			state = check_op_valid(qp, pkt);
			break;
		case RESPST_CHK_RESOURCE:
			state = check_resource(qp, pkt);
			break;
		case RESPST_CHK_LENGTH:
			state = rxe_resp_check_length(qp, pkt);
			break;
		case RESPST_CHK_RKEY:
			state = check_rkey(qp, pkt);
			break;
		case RESPST_EXECUTE:
			state = execute(qp, pkt);
			break;
		case RESPST_COMPLETE:
			state = do_complete(qp, pkt);
			break;
		case RESPST_READ_REPLY:
			state = read_reply(qp, pkt);
			break;
		case RESPST_ATOMIC_REPLY:
			state = atomic_reply(qp, pkt);
			break;
		case RESPST_ATOMIC_WRITE_REPLY:
			state = atomic_write_reply(qp, pkt);
			break;
		case RESPST_PROCESS_FLUSH:
			state = process_flush(qp, pkt);
			break;
		case RESPST_ACKNOWLEDGE:
			state = acknowledge(qp, pkt);
			break;
		case RESPST_CLEANUP:
			state = cleanup(qp, pkt);
			break;
		case RESPST_DUPLICATE_REQUEST:
			state = duplicate_request(qp, pkt);
			break;
                ....
		case RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}
			goto done;
		case RESPST_EXIT:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}
			goto exit;
		case RESPST_ERROR:
			qp->resp.goto_error = 0;
			rxe_dbg_qp(qp, "moved to error state\n");
			rxe_qp_error(qp);
			goto exit;

		default:
			WARN_ON_ONCE(1);
		}
	}
done:
	ret = 0;
	goto out;
exit:
	ret = -EAGAIN;
out:
	return ret;
}
```

`rxe_receiver`函数检查QP有效后，初始化状态机，按照状态机处理请求包。主要的状态如下：

* `RESPST_GET_REQ`获取请求包

`get_req`函数从请求队列获取请求包，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static inline enum resp_states get_req(struct rxe_qp *qp, struct rxe_pkt_info **pkt_p)
{
	struct sk_buff *skb;
        // 从请求队列获取请求包
	skb = skb_peek(&qp->req_pkts);
	if (!skb) return RESPST_EXIT;
        // 将skb转换为pkt
	*pkt_p = SKB_TO_PKT(skb);
        // 根据是否是回复包，返回不同的状态
	return (qp->resp.res) ? RESPST_READ_REPLY : RESPST_CHK_PSN;
}
```

* `RESPST_CHK_PSN`检查PSN

`check_psn`函数检查PSN, 检查PSN是否超出范围或重复请求，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states check_psn(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
        // 计算PSN差值
	int diff = psn_compare(pkt->psn, qp->resp.psn);
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (diff > 0) {
                        // 如果PSN大于当前PSN
			if (qp->resp.sent_psn_nak) return RESPST_CLEANUP;
			qp->resp.sent_psn_nak = 1;
			rxe_counter_inc(rxe, RXE_CNT_OUT_OF_SEQ_REQ);
                        // 发送PSN超出范围
			return RESPST_ERR_PSN_OUT_OF_SEQ;
		} else if (diff < 0) {
			rxe_counter_inc(rxe, RXE_CNT_DUP_REQ);
                        // 如果PSN小于当前PSN，说明是重复请求
			return RESPST_DUPLICATE_REQUEST;
		}
		if (qp->resp.sent_psn_nak) qp->resp.sent_psn_nak = 0;
		break;

	case IB_QPT_UC:
                // 检查是否丢弃消息
		if (qp->resp.drop_msg || diff != 0) {
			if (pkt->mask & RXE_START_MASK) {
				qp->resp.drop_msg = 0;
				return RESPST_CHK_OP_SEQ;
			}
			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	default:
		break;
	}
	return RESPST_CHK_OP_SEQ;
}
```

* `RESPST_CHK_OP_SEQ`检查操作序列

`check_op_seq`函数检查操作的执行顺序，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states check_op_seq(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
                ...
        	break;
	case IB_QPT_UC:
                ...
		break;
	default:
		return RESPST_CHK_OP_VALID;
	}
}
```

* `RESPST_CHK_OP_VALID`检查操作码是否有效

`check_op_valid`函数检查操作是否有效，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states check_op_valid(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
                // 检查QP属性访问权限
		if (!check_qp_attr_access(qp, pkt))
			return RESPST_ERR_UNSUPPORTED_OPCODE;
		break;
	case IB_QPT_UC:
		if ((pkt->mask & RXE_WRITE_MASK) &&
		    !(qp->attr.qp_access_flags & IB_ACCESS_REMOTE_WRITE)) {
			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	case IB_QPT_UD:
	case IB_QPT_GSI:
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	return RESPST_CHK_RESOURCE;
}
```

* `RESPST_CHK_RESOURCE`检查资源

`check_resource`函数检查资源，获取接收队列的WQE， 如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states check_resource(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	struct rxe_srq *srq = qp->srq;
        // ATOMIC相关检查
	if (pkt->mask & (RXE_READ_OR_ATOMIC_MASK | RXE_ATOMIC_WRITE_MASK)) {
		if (likely(qp->attr.max_dest_rd_atomic > 0))
			return RESPST_CHK_LENGTH;
		else
			return RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & RXE_RWR_MASK) {
                // 从srq获取WQE
		if (srq) return get_srq_wqe(qp);
                // 从rq获取WQE
		qp->resp.wqe = queue_head(qp->rq.queue, QUEUE_TYPE_FROM_CLIENT);
		return (qp->resp.wqe) ? RESPST_CHK_LENGTH : RESPST_ERR_RNR;
	}
	return RESPST_CHK_LENGTH;
}
```

* `RESPST_CHK_LENGTH`检查消息长度

`check_length`函数检查消息长度是否有效，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states rxe_resp_check_length(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
        ...
        if (pkt->mask & RXE_RETH_MASK) {
                // 检查RETH长度是否超出范围
		if (reth_len(pkt) > (1U << 31)) {
			rxe_dbg_qp(qp, "dma length too long\n");
			return RESPST_ERR_LENGTH;
		}
	}

	if (pkt->mask & RXE_RDMA_OP_MASK)
		return RESPST_CHK_RKEY;
	else
		return RESPST_EXECUTE;
}
```

* `RESPST_CHK_RKEY`检查RKEY

`check_rkey`函数解析RKEY，转化为`mr`或`mw`, 如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states check_rkey(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	struct rxe_mr *mr = NULL;
	struct rxe_mw *mw = NULL;
	u64 va;
	u32 rkey;
	u32 resid;
	u32 pktlen;
	int mtu = qp->mtu;
	enum resp_states state;
	int access = 0;

        // 解析RETH/ATMETH头, 获取数据写入的地址
	if (pkt->mask & (RXE_READ_OR_WRITE_MASK | RXE_ATOMIC_WRITE_MASK)) {
                // 解析RETH头，获取数据写入的地址
		if (pkt->mask & RXE_RETH_MASK)  qp_resp_from_reth(qp, pkt);
		access = (pkt->mask & RXE_READ_MASK) ? IB_ACCESS_REMOTE_READ
						     : IB_ACCESS_REMOTE_WRITE;
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		u32 flush_type = feth_plt(pkt);
                // 解析RETH头，获取数据写入的地址
		if (pkt->mask & RXE_RETH_MASK) qp_resp_from_reth(qp, pkt);

		if (flush_type & IB_FLUSH_GLOBAL) access |= IB_ACCESS_FLUSH_GLOBAL;
		if (flush_type & IB_FLUSH_PERSISTENT) access |= IB_ACCESS_FLUSH_PERSISTENT;
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
                // 解析ATMETH头，获取数据写入的地址
		qp_resp_from_atmeth(qp, pkt);
		access = IB_ACCESS_REMOTE_ATOMIC;
	} else {
		/* shouldn't happen */
		WARN_ON(1);
	}

        // 检查零字节读写操作是否设置了addr或rkey
	if ((pkt->mask & RXE_READ_OR_WRITE_MASK) &&
	    (pkt->mask & RXE_RETH_MASK) && reth_len(pkt) == 0) {
		qp->resp.mr = NULL;
		return RESPST_EXECUTE;
	}
        // 获取va, rkey, resid, pktlen
	va	= qp->resp.va;
	rkey	= qp->resp.rkey;
	resid	= qp->resp.resid;
	pktlen	= payload_size(pkt);

	if (rkey_is_mw(rkey)) {
                // 检查MW是否存在
		mw = rxe_lookup_mw(qp, access, rkey);
		if (!mw) { ... }
		mr = mw->mr;
		if (!mr) { ... }
		if (mw->access & IB_ZERO_BASED)
			qp->resp.offset = mw->addr;
		rxe_get(mr);
		rxe_put(mw);
		mw = NULL;
	} else {
                // 检查MR是否存在
		mr = lookup_mr(qp->pd, access, rkey, RXE_LOOKUP_REMOTE);
		if (!mr) { ... }
	}

	if (pkt->mask & RXE_FLUSH_MASK) {
                // 检查是否为FLUSH MR
		if (feth_sel(pkt) == IB_FLUSH_MR) goto skip_check_range;
	}
        // 检查MR范围是否有效
	if (mr_check_range(mr, va + qp->resp.offset, resid)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

skip_check_range:
        // 检查写入长度是否超出范围
	if (pkt->mask & (RXE_WRITE_MASK | RXE_ATOMIC_WRITE_MASK)) { ...	}

	WARN_ON_ONCE(qp->resp.mr);
        // 设置响应MR
	qp->resp.mr = mr;
	return RESPST_EXECUTE;

err:
	qp->resp.mr = NULL;
	if (mr) rxe_put(mr);
	if (mw) rxe_put(mw);
	return state;
}
```

`qp_resp_from_reth`函数从skb中解析RETH头，获取数据写入的地址，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static void qp_resp_from_reth(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
        // 获取RETH头中的va, rkey, length
	unsigned int length = reth_len(pkt);
	qp->resp.va = reth_va(pkt);
	qp->resp.offset = 0;
	qp->resp.resid = length;
	qp->resp.length = length;
	if (pkt->mask & RXE_READ_OR_WRITE_MASK && length == 0)
		qp->resp.rkey = 0;
	else
		qp->resp.rkey = reth_rkey(pkt);
}
```

`lookup_mr`函数根据RKEY查找MR，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_mr.c
struct rxe_mr *lookup_mr(struct rxe_pd *pd, int access, u32 key,
			 enum rxe_mr_lookup_type type)
{
	struct rxe_mr *mr;
	struct rxe_dev *rxe = to_rdev(pd->ibpd.device);
	int index = key >> 8;
        // 从MR池获取MR
	mr = rxe_pool_get_index(&rxe->mr_pool, index);
	if (!mr) return NULL;

        // 检查MR是否有效
	if (unlikely((type == RXE_LOOKUP_LOCAL && mr->lkey != key) ||
		     (type == RXE_LOOKUP_REMOTE && mr->rkey != key) ||
		     mr_pd(mr) != pd || ((access & mr->access) != access) ||
		     mr->state != RXE_MR_STATE_VALID)) {
		rxe_put(mr);
		mr = NULL;
	}
	return mr;
}
```

* `RESPST_EXECUTE`执行响应

`execute`函数执行响应，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states execute(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	enum resp_states err;
	struct sk_buff *skb = PKT_TO_SKB(pkt);
	union rdma_network_hdr hdr;

	if (pkt->mask & RXE_SEND_MASK) {
		if (qp_type(qp) == IB_QPT_UD || qp_type(qp) == IB_QPT_GSI) {
			if (skb->protocol == htons(ETH_P_IP)) {
				memset(&hdr.reserved, 0, sizeof(hdr.reserved));
				memcpy(&hdr.roce4grh, ip_hdr(skb), sizeof(hdr.roce4grh));
				err = send_data_in(qp, &hdr, sizeof(hdr));
			} else {
				err = send_data_in(qp, ipv6_hdr(skb), sizeof(hdr));
			}
			if (err) return err;
		}
                // 处理发送的数据
		err = send_data_in(qp, payload_addr(pkt), payload_size(pkt));
		if (err) return err;
	} else if (pkt->mask & RXE_WRITE_MASK) {
                // 处理写入数据
		err = write_data_in(qp, pkt);
		if (err) return err;
	} else if (pkt->mask & RXE_READ_MASK) {
                // 处理RDMA Read，增加MSN
		qp->resp.msn++;
		return RESPST_READ_REPLY;
	} else if (pkt->mask & RXE_ATOMIC_MASK) {
		return RESPST_ATOMIC_REPLY;
	} else if (pkt->mask & RXE_ATOMIC_WRITE_MASK) {
		return RESPST_ATOMIC_WRITE_REPLY;
	} else if (pkt->mask & RXE_FLUSH_MASK) {
		return RESPST_PROCESS_FLUSH;
	} else {
		/* Unreachable */
		WARN_ON_ONCE(1);
	}

	if (pkt->mask & RXE_IETH_MASK) {
		u32 rkey = ieth_rkey(pkt);
                // 处理IETH头，无效化RKEY
		err = invalidate_rkey(qp, rkey);
		if (err) return RESPST_ERR_INVALIDATE_RKEY;
	}

	if (pkt->mask & RXE_END_MASK)
                // 处理END头，增加MSN
		qp->resp.msn++;

        // 设置下一个期望的PSN
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;
        // 设置响应操作码和状态
	qp->resp.opcode = pkt->opcode;
	qp->resp.status = IB_WC_SUCCESS;

	if (pkt->mask & RXE_COMP_MASK)
		return RESPST_COMPLETE;
	else if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}
```

`send_data_in`函数处理发送的数据，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states send_data_in(struct rxe_qp *qp, void *data_addr, int data_len)
{
	int err;
        // 复制数据到WQE DMA区域
	err = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE, &qp->resp.wqe->dma,
			data_addr, data_len, RXE_TO_MR_OBJ);
	if (unlikely(err))
		return (err == -ENOSPC) ? RESPST_ERR_LENGTH : RESPST_ERR_MALFORMED_WQE;
	return RESPST_NONE;
}
```

`write_data_in`函数将数据写入mr中，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states write_data_in(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt)
{
	enum resp_states rc = RESPST_NONE;
	int	err;
	int data_len = payload_size(pkt);
        // 复制数据到MR
	err = rxe_mr_copy(qp->resp.mr, qp->resp.va + qp->resp.offset,
			  payload_addr(pkt), data_len, RXE_TO_MR_OBJ);
	if (err) {
		rc = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}
        // 更新偏移量和剩余长度
	qp->resp.va += data_len;
	qp->resp.resid -= data_len;
out:
	return rc;
}
```

* `RESPST_COMPLETE`完成响应

`do_complete`函数完成响应，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states do_complete(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	struct rxe_cqe cqe;
	struct ib_wc *wc = &cqe.ibwc;
	struct ib_uverbs_wc *uwc = &cqe.uibwc;
	struct rxe_recv_wqe *wqe = qp->resp.wqe;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	unsigned long flags;

	if (!wqe) goto finish;
        // 初始化CQE
	memset(&cqe, 0, sizeof(cqe));
        // 设置CQE字段
	if (qp->rcq->is_user) {
		uwc->status		= qp->resp.status;
		uwc->qp_num		= qp->ibqp.qp_num;
		uwc->wr_id		= wqe->wr_id;
	} else {
		wc->status		= qp->resp.status;
		wc->qp			= &qp->ibqp;
		wc->wr_id		= wqe->wr_id;
	}

	if (wc->status == IB_WC_SUCCESS) {
		rxe_counter_inc(rxe, RXE_CNT_RDMA_RECV);
                // 设置操作码和字节长度
		wc->opcode = (pkt->mask & RXE_IMMDT_MASK && pkt->mask & RXE_WRITE_MASK) ?
					IB_WC_RECV_RDMA_WITH_IMM : IB_WC_RECV;
		wc->byte_len = (pkt->mask & RXE_IMMDT_MASK && pkt->mask & RXE_WRITE_MASK) ?
					qp->resp.length : wqe->dma.length - wqe->dma.resid;
                // 设置其他字段
		if (qp->rcq->is_user) {
			uwc->wc_flags = IB_WC_GRH;
			if (pkt->mask & RXE_IMMDT_MASK) {
				uwc->wc_flags |= IB_WC_WITH_IMM;
				uwc->ex.imm_data = immdt_imm(pkt);
			}
			if (pkt->mask & RXE_IETH_MASK) {
				uwc->wc_flags |= IB_WC_WITH_INVALIDATE;
				uwc->ex.invalidate_rkey = ieth_rkey(pkt);
			}
			if (pkt->mask & RXE_DETH_MASK)
				uwc->src_qp = deth_sqp(pkt);
			uwc->port_num		= qp->attr.port_num;
		} else {
                        ...
		}
	} else {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			rxe_err_qp(qp, "non-flush error status = %d\n", wc->status);
	}

	if (!qp->srq)
                // 增加RQ消费者指针
		queue_advance_consumer(qp->rq.queue, QUEUE_TYPE_FROM_CLIENT);
	qp->resp.wqe = NULL;
        // 提交CQE
	if (rxe_cq_post(qp->rcq, &cqe, pkt ? bth_se(pkt) : 1))
		return RESPST_ERR_CQ_OVERFLOW;

finish:
	spin_lock_irqsave(&qp->state_lock, flags);
	if (unlikely(qp_state(qp) == IB_QPS_ERR)) {
		spin_unlock_irqrestore(&qp->state_lock, flags);
		return RESPST_CHK_RESOURCE;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

	if (unlikely(!pkt)) return RESPST_DONE;
        // 根据QP类型返回不同的状态
	if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}
```

`rxe_cq_post`提交CQE，将CQE添加到CQ队列中，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
int rxe_cq_post(struct rxe_cq *cq, struct rxe_cqe *cqe, int solicited)
{
	struct ib_event ev;
	int full;
	void *addr;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
        // 检查CQ队列是否已满
	full = queue_full(cq->queue, QUEUE_TYPE_TO_CLIENT);
	if (unlikely(full)) { ... }

        // 获取CQ队列生产者地址, 并将CQE复制到生产者地址
	addr = queue_producer_addr(cq->queue, QUEUE_TYPE_TO_CLIENT);
	memcpy(addr, cqe, sizeof(*cqe));
        // 增加CQ队列生产者指针
	queue_advance_producer(cq->queue, QUEUE_TYPE_TO_CLIENT);

	if ((cq->notify & IB_CQ_NEXT_COMP) ||
	    (cq->notify & IB_CQ_SOLICITED && solicited)) {
		cq->notify = 0;
        	// 触发CQ事件
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);
	return 0;
}
```

* `RESPST_ACKNOWLEDGE`确认响应

`acknowledge`通知接收完成，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states acknowledge(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
        // 检查QP类型是否为RC
	if (qp_type(qp) != IB_QPT_RC)
		return RESPST_CLEANUP;
        // 根据不同的设置发送ack确认
	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED)
		send_ack(qp, qp->resp.aeth_syndrome, pkt->psn);
	else if (pkt->mask & RXE_ATOMIC_MASK)
		send_atomic_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);
	else if (pkt->mask & (RXE_FLUSH_MASK | RXE_ATOMIC_WRITE_MASK))
		send_read_response_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);
	else if (bth_ack(pkt))
		send_ack(qp, AETH_ACK_UNLIMITED, pkt->psn);

	return RESPST_CLEANUP;
}
```

`send_ack`通过skb发送ack确认，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static int send_common_ack(struct rxe_qp *qp, u8 syndrome, u32 psn, int opcode, const char *msg)
{
	int err;
	struct rxe_pkt_info ack_pkt;
	struct sk_buff *skb;
        // 准备ack确认包
	skb = prepare_ack_packet(qp, &ack_pkt, opcode, 0, psn, syndrome);
	if (!skb) return -ENOMEM;
        // 发送ack确认包
	err = rxe_xmit_packet(qp, &ack_pkt, skb);
	if (err) rxe_dbg_qp(qp, "Failed sending %s\n", msg);

	return err;
}
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static int send_ack(struct rxe_qp *qp, u8 syndrome, u32 psn)
{
	return send_common_ack(qp, syndrome, psn, IB_OPCODE_RC_ACKNOWLEDGE, "ACK");
}
```

* `RESPST_CLEANUP`清理响应

`cleanup`清理响应，如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_resp.c
static enum resp_states cleanup(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	struct sk_buff *skb;

	if (pkt) {
                // 从`req_pkts`队列中弹出skb
		skb = skb_dequeue(&qp->req_pkts);
		rxe_put(qp);
		kfree_skb(skb);
		ib_device_put(qp->ibqp.device);
	}

	if (qp->resp.mr) {
                // 释放响应MR
		rxe_put(qp->resp.mr);
		qp->resp.mr = NULL;
	}
	return RESPST_DONE;
}
```

* `RESPST_DONE`完成响应

检查是否有其他响应待处理，无则返回`0`。


#### 3.11.4 `resp_pkts`的处理过程

`pkt`没有设置`RXE_REQ_MASK`，说明是响应包。`rxe_comp_queue_pkt`函数将skb加入响应队列，并唤醒发送任务。`send_task`设置的执行接口为`rxe_sender`, 如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_qp.c
int rxe_sender(struct rxe_qp *qp)
{
	int req_ret;
	int comp_ret;
	// 处理发送队列
	req_ret = rxe_requester(qp);
	// 处理应答队列
	comp_ret = rxe_completer(qp);

	return (req_ret && comp_ret) ? -EAGAIN : 0;
}
```

前面我们分析了`rxe_requester`函数，它负责处理发送队列中的请求包。接下来我们分析`rxe_completer`函数，它负责处理响应队列中的响应包。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
int rxe_completer(struct rxe_qp *qp)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_send_wqe *wqe = NULL;
	struct sk_buff *skb = NULL;
	struct rxe_pkt_info *pkt = NULL;
	enum comp_state state;
	int ret;
	unsigned long flags;

	qp->req.again = 0;

	spin_lock_irqsave(&qp->state_lock, flags);
        // 检查QP是否有效
	if (!qp->valid || qp_state(qp) == IB_QPS_ERR ||
			  qp_state(qp) == IB_QPS_RESET) {
		bool notify = qp->valid && (qp_state(qp) == IB_QPS_ERR);
		drain_resp_pkts(qp);
		flush_send_queue(qp, notify);
		spin_unlock_irqrestore(&qp->state_lock, flags);
		goto exit;
	}
	spin_unlock_irqrestore(&qp->state_lock, flags);

        // 检查是否有超时响应包
	if (qp->comp.timeout) {
		qp->comp.timeout_retry = 1;
		qp->comp.timeout = 0;
	} else {
		qp->comp.timeout_retry = 0;
	}

	if (qp->req.need_retry) goto exit;

        // 初始化状态机
	state = COMPST_GET_ACK;
	while (1) {
		rxe_dbg_qp(qp, "state = %s\n", comp_state_name[state]);
		switch (state) {
		case COMPST_GET_ACK:
			skb = skb_dequeue(&qp->resp_pkts);
			if (skb) {
				pkt = SKB_TO_PKT(skb);
				qp->comp.timeout_retry = 0;
			}
			state = COMPST_GET_WQE;
			break;
		case COMPST_GET_WQE:
			state = get_wqe(qp, pkt, &wqe);
			break;
		case COMPST_CHECK_PSN:
			state = check_psn(qp, pkt, wqe);
			break;
		case COMPST_CHECK_ACK:
			state = check_ack(qp, pkt, wqe);
			break;
		case COMPST_READ:
			state = do_read(qp, pkt, wqe);
			break;
		case COMPST_ATOMIC:
			state = do_atomic(qp, pkt, wqe);
			break;
		case COMPST_WRITE_SEND:
			if (wqe->state == wqe_state_pending && wqe->last_psn == pkt->psn)
				state = COMPST_COMP_ACK;
			else
				state = COMPST_UPDATE_COMP;
			break;
		case COMPST_COMP_ACK:
			state = complete_ack(qp, pkt, wqe);
			break;
		case COMPST_COMP_WQE:
			state = complete_wqe(qp, pkt, wqe);
			break;
		case COMPST_UPDATE_COMP:
			if (pkt->mask & RXE_END_MASK)
				qp->comp.opcode = -1;
			else
				qp->comp.opcode = pkt->opcode;

			if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
				qp->comp.psn = (pkt->psn + 1) & BTH_PSN_MASK;

			if (qp->req.wait_psn) {
				qp->req.wait_psn = 0;
				qp->req.again = 1;
			}
			state = COMPST_DONE;
			break;
		case COMPST_DONE:
			goto done;
		case COMPST_EXIT:
			if (qp->comp.timeout_retry && wqe) {
				state = COMPST_ERROR_RETRY;
				break;
			}
			reset_retry_timer(qp);
			goto exit;
		case COMPST_ERROR_RETRY:
                        ...
			break;
		case COMPST_RNR_RETRY:
                        ...
			break;
		case COMPST_ERROR:
			WARN_ON_ONCE(wqe->status == IB_WC_SUCCESS);
			do_complete(qp, wqe);
			rxe_qp_error(qp);
			goto exit;
		}
	}
done:
	ret = 0;
	goto out;
exit:
	ret = (qp->req.again) ? 0 : -EAGAIN;
out:
	qp->req.again = 0;
	if (pkt)
		free_pkt(pkt);
	return ret;
}
```

`rxe_completer`函数检查QP有效后，初始化状态机，按照状态机处理响应包。主要的处理状态如下：

* `COMPST_GET_ACK`获取ACK

`COMPST_GET_ACK`从`resp_pkts`队列中弹出skb，将其转换为`pkt`。

* `COMPST_GET_WQE`获取WQE

`get_wqe`从sq队列中获取第一个wqe, 并检查其状态。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state get_wqe(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt,
				      struct rxe_send_wqe **wqe_p)
{
	struct rxe_send_wqe *wqe;
        // 从sq队列中获取第一个wqe
	wqe = queue_head(qp->sq.queue, QUEUE_TYPE_FROM_CLIENT);
	*wqe_p = wqe;

        // 如果没有wqe或wqe状态为posted，说明没有wqe需要处理
	if (!wqe || wqe->state == wqe_state_posted)
		return pkt ? COMPST_DONE : COMPST_EXIT;
        // 如果wqe状态为done，说明wqe已完成，不需要ack
	if (wqe->state == wqe_state_done) return COMPST_COMP_WQE;

        // 如果wqe状态为error，说明wqe发生错误，需要处理错误
	if (wqe->state == wqe_state_error) return COMPST_ERROR;
        // 如果有pkt，需要检查PSN
	return pkt ? COMPST_CHECK_PSN : COMPST_EXIT;
}
```

* `COMPST_CHECK_PSN`检查PSN

`check_psn`检查ack的PSN是否与wqe的PSN匹配。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state check_psn(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	s32 diff;
        // 检查ack的PSN是否大于wqe的last_psn
	diff = psn_compare(pkt->psn, wqe->last_psn);
	if (diff > 0) { ... }

        // 检查ack的PSN是否为期待的PSN
	diff = psn_compare(pkt->psn, qp->comp.psn);
	if (diff < 0) {
		...
	} else if ((diff > 0) && (wqe->mask & WR_ATOMIC_OR_READ_MASK)) {
		return COMPST_DONE;
	} else {
		return COMPST_CHECK_ACK;
	}
}
```

* `COMPST_CHECK_ACK`检查ACK

`check_ack`检查ack的psn和opcode是否匹配。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state check_ack(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	unsigned int mask = pkt->mask;
	u8 syn;
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);

	switch (qp->comp.opcode) {
                ...
        }

	switch (pkt->opcode) {
                ...
        }
}
```

* `COMPST_READ`读取skb数据

`do_read`读取skb数据到wqe的buf中。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state do_read(struct rxe_qp *qp,
				      struct rxe_pkt_info *pkt,
				      struct rxe_send_wqe *wqe)
{
	int ret;
        // 复制skb数据到wqe的buf中
	ret = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE,
			&wqe->dma, payload_addr(pkt),
			payload_size(pkt), RXE_TO_MR_OBJ);
	if (ret) {
		wqe->status = IB_WC_LOC_PROT_ERR;
		return COMPST_ERROR;
	}
        // 如果wqe的resid为0且ack为end，说明读取数据完成
	if (wqe->dma.resid == 0 && (pkt->mask & RXE_END_MASK))
		return COMPST_COMP_ACK

	return COMPST_UPDATE_COMP;
}
```

* `COMPST_ATOMIC`读取atomic数据

`do_atomic`读取atomic数据到wqe的buf中。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state do_atomic(struct rxe_qp *qp,
					struct rxe_pkt_info *pkt,
					struct rxe_send_wqe *wqe)
{
	int ret;
        // 获取
	u64 atomic_orig = atmack_orig(pkt);
        // 复制atomic
	ret = copy_data(qp->pd, IB_ACCESS_LOCAL_WRITE, &wqe->dma, &atomic_orig, sizeof(u64), RXE_TO_MR_OBJ);
	if (ret) {
		wqe->status = IB_WC_LOC_PROT_ERR;
		return COMPST_ERROR;
	}
	return COMPST_COMP_ACK;
}
```

* `COMPST_WRITE_SEND`处理写入数据

`COMPST_WRITE_SEND`检查wqe状态，如果wqe状态为pending且last_psn与ack的psn匹配，说明写入数据已完成，可以发送ack确认；否则需要更新完成状态。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
int rxe_completer(struct rxe_qp *qp)
{
        ...
		switch (state) {
                        ...
		case COMPST_WRITE_SEND:
			if (wqe->state == wqe_state_pending &&
			    wqe->last_psn == pkt->psn)
				state = COMPST_COMP_ACK;
			else
				state = COMPST_UPDATE_COMP;
			break;
                        ...
                }
        ...
}
```

* `COMPST_COMP_ACK`处理ack确认

`complete_ack`确认ack，并通知用户空间wqe已完成。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state complete_ack(struct rxe_qp *qp,
					   struct rxe_pkt_info *pkt,
					   struct rxe_send_wqe *wqe)
{
	if (wqe->has_rd_atomic) {
		wqe->has_rd_atomic = 0;
		atomic_inc(&qp->req.rd_atomic);
		if (qp->req.need_rd_atomic) {
			qp->comp.timeout_retry = 0;
			qp->req.need_rd_atomic = 0;
			qp->req.again = 1;
		}
	}
        // 检查sq是否 drained
	comp_check_sq_drain_done(qp);
        // 完成wqe
	do_complete(qp, wqe);

	if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
		return COMPST_UPDATE_COMP;
	else
		return COMPST_DONE;
}
```

`do_complete`表示完成wqe，向用户空间通知wqe已完成。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static void do_complete(struct rxe_qp *qp, struct rxe_send_wqe *wqe)
{
	struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
	struct rxe_cqe cqe;
	bool post;
        // 检查是否需要发送完成通知
	post = ((qp->sq_sig_type == IB_SIGNAL_ALL_WR) ||
			(wqe->wr.send_flags & IB_SEND_SIGNALED) ||
			wqe->status != IB_WC_SUCCESS);
        // 构造完成通知
	if (post) make_send_cqe(qp, wqe, &cqe);
        // 移动sq的consumer指针
	queue_advance_consumer(qp->sq.queue, QUEUE_TYPE_FROM_CLIENT);
        // 发送完成通知
	if (post) rxe_cq_post(qp->scq, &cqe, 0);

	if (wqe->wr.opcode == IB_WR_SEND ||
	    wqe->wr.opcode == IB_WR_SEND_WITH_IMM ||
	    wqe->wr.opcode == IB_WR_SEND_WITH_INV)
		rxe_counter_inc(rxe, RXE_CNT_RDMA_SEND);

        // 检查是否需要通知req重新运行
	if (qp->req.wait_fence) {
		qp->req.wait_fence = 0;
		qp->req.again = 1;
	}
}
```

`make_send_cqe`构造完成发送队列的通知。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static void make_send_cqe(struct rxe_qp *qp, struct rxe_send_wqe *wqe,
			  struct rxe_cqe *cqe)
{
	struct ib_wc *wc = &cqe->ibwc;
	struct ib_uverbs_wc *uwc = &cqe->uibwc;

	memset(cqe, 0, sizeof(*cqe));
        // 填充wc或uwc
	if (!qp->is_user) {
		wc->wr_id = wqe->wr.wr_id;
		wc->status = wqe->status;
		wc->qp = &qp->ibqp;
	} else {
		uwc->wr_id = wqe->wr.wr_id;
		uwc->status = wqe->status;
		uwc->qp_num = qp->ibqp.qp_num;
	}

	if (wqe->status == IB_WC_SUCCESS) {
        	// 根据用户空间或内核空间填充不同的字段
		if (!qp->is_user) {
			wc->opcode = wr_to_wc_opcode(wqe->wr.opcode);
			if (wqe->wr.opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
			    wqe->wr.opcode == IB_WR_SEND_WITH_IMM)
				wc->wc_flags = IB_WC_WITH_IMM;
			wc->byte_len = wqe->dma.length;
		} else {
			uwc->opcode = wr_to_wc_opcode(wqe->wr.opcode);
			if (wqe->wr.opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
			    wqe->wr.opcode == IB_WR_SEND_WITH_IMM)
				uwc->wc_flags = IB_WC_WITH_IMM;
			uwc->byte_len = wqe->dma.length;
		}
	} else {
		if (wqe->status != IB_WC_WR_FLUSH_ERR)
			rxe_err_qp(qp, "non-flush error status = %d\n", wqe->status);
	}
}
```

* `COMPST_COMP_WQE`处理wqe完成通知

`complete_wqe`函数处理wqe完成通知。如下：

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
static inline enum comp_state complete_wqe(struct rxe_qp *qp,
					   struct rxe_pkt_info *pkt,
					   struct rxe_send_wqe *wqe)
{
        // 等待wqe完成
	if (pkt && wqe->state == wqe_state_pending) {
		if (psn_compare(wqe->last_psn, qp->comp.psn) >= 0) {
			qp->comp.psn = (wqe->last_psn + 1) & BTH_PSN_MASK;
			qp->comp.opcode = -1;
		}
		if (qp->req.wait_psn) {
			qp->req.wait_psn = 0;
			qp->req.again = 1;
		}
	}
        // 完成wqe
	do_complete(qp, wqe);
        // 获取下一个wqe
	return COMPST_GET_WQE;
}
```

* `COMPST_UPDATE_COMP`更新完成状态

`COMPST_UPDATE_COMP`更新comp和req的状态，如下:

```c
// file: drivers/infiniband/sw/rxe/rxe_comp.c
int rxe_completer(struct rxe_qp *qp)
{
        ...
		switch (state) {
                        ...
		case COMPST_UPDATE_COMP:
			if (pkt->mask & RXE_END_MASK)
				qp->comp.opcode = -1;
			else
				qp->comp.opcode = pkt->opcode;
                        // 更新psn
			if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
				qp->comp.psn = (pkt->psn + 1) & BTH_PSN_MASK;

			if (qp->req.wait_psn) {
				qp->req.wait_psn = 0;
				qp->req.again = 1;
			}

			state = COMPST_DONE;
			break;
                        ...
                }
        ...
}
```

* `COMPST_DONE`完成处理

`COMPST_DONE`表示完成处理，返回`0`。

### 3.12 用户空间获取完成通知

内核空间在收发完成后，会向用户空间发送完成通知。用户空间可以通过`poll`机制来获取完成通知。如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
int main(int argc, char *argv[])
{
        ...
		{
			int ne, i;
			struct ibv_wc wc[2];

			do {
                                // 轮询完成队列
				ne = ibv_poll_cq(pp_cq(ctx), 2, wc);
				if (ne < 0) { ... }
			} while (!use_event && ne < 1);

			for (i = 0; i < ne; ++i) {
                                // 解析完成通知
				ret = parse_single_wc(ctx, &scnt, &rcnt, &routs, iters,
						      wc[i].wr_id, wc[i].status, 0, &ts);
				if (ret) { ... }
			}
		}
        ...
}
```

`ibv_poll_cq`获取完成队列的通知。如下：

```c
// file: rdma-core/libibverbs/verbs.h
static inline int ibv_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	return cq->context->ops.poll_cq(cq, num_entries, wc);
}
```

#### 3.12.1 用户空间`rxe`获取完成通知

`rxe`设置的`.poll_cq`接口为`rxe_poll_cq`, 其实现如下：

```c
// file: rdma-core/providers/rxe/rxe.c
static int rxe_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_queue_buf *q;
	int npolled;
	uint8_t *src;

	pthread_spin_lock(&cq->lock);
        // 获取完成队列
	q = cq->queue;

	for (npolled = 0; npolled < ne; ++npolled, ++wc) {
		if (queue_empty(q)) break;
                // 从完成队列中获取完成通知
		src = consumer_addr(q);
		memcpy(wc, src, sizeof(*wc));
		advance_consumer(q);
	}

	pthread_spin_unlock(&cq->lock);
	return npolled;
}
```

#### 3.12.2 用户空间处理完成通知

用户空间在获取完成通知后，根据`wr_id`和`status`来处理完成通知，如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static inline int parse_single_wc(struct pingpong_context *ctx, int *scnt,
				  int *rcnt, int *routs, int iters,
				  uint64_t wr_id, enum ibv_wc_status status,
				  uint64_t completion_timestamp,
				  struct ts_params *ts)
{
        ...
	switch ((int)wr_id) {
        // 处理发送通知
	case PINGPONG_SEND_WRID:
		++(*scnt);
		break;
        // 处理接收通知
	case PINGPONG_RECV_WRID:
		if (--(*routs) <= 1) {
                        // 接收完成后，提交接收请求
			*routs += pp_post_recv(ctx, ctx->rx_depth - *routs);
			if (*routs < ctx->rx_depth) { ... }
		}
		++(*rcnt);
		break;
	default:
		fprintf(stderr, "Completion for unknown wr_id %d\n", (int)wr_id);
		return 1;
	}

	ctx->pending &= ~(int)wr_id;
	if (*scnt < iters && !ctx->pending) {
                // 未达到次数，提交发送请求
		if (pp_post_send(ctx)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}
		ctx->pending = PINGPONG_RECV_WRID | PINGPONG_SEND_WRID;
	}
	return 0;
}
```

### 3.13 用户空间清理

用户空间在完成通信后，需要清理资源，如下：

```c
// file: rdma-core/libibverbs/examples/rc_pingpong.c
static int pp_close_ctx(struct pingpong_context *ctx)
{
        // 销毁qp
	if (ibv_destroy_qp(ctx->qp)) { ... }
        // 销毁cq
	if (ibv_destroy_cq(pp_cq(ctx))) { ... }
        // 注销mr
	if (ibv_dereg_mr(ctx->mr)) { ... }

	if (ctx->dm) {
                // 释放dm
		if (ibv_free_dm(ctx->dm)) { ... }
	}
        // 释放pd
	if (ibv_dealloc_pd(ctx->pd)) { ... }

	if (ctx->channel) {
                // 销毁comp channel
		if (ibv_destroy_comp_channel(ctx->channel)) { ... }
	}
        // 关闭设备
	if (ibv_close_device(ctx->context)) { ... }

        // 释放buf
	free(ctx->buf);
	free(ctx);
	return 0;
}
```

`ibv_destroy_qp`, `ibv_destroy_cq`, `ibv_dereg_mr`, `ibv_free_dm`, `ibv_dealloc_pd`, `ibv_destroy_comp_channel`, `ibv_close_device` 等接口实现与打开接口类似，都是调用设备的`ops`接口。用户空间通知内核空间实现，就不一一介绍。

## 4 总结

通过本文，我们以`rc_pingpong`示例分析了使用ibverbs进行RDMA通信的基本原理和实现。我们详细介绍了ibverbs的接口的实现机制，通过本文的分析，我们可以更好地理解ibverbs的工作原理和实现机制。

## 参考资料

* [RDMA杂谈](https://zhuanlan.zhihu.com/p/164908617)

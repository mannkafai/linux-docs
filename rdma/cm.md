# RDMA Connection Manager (CM)的内核实现

## 1 简介

RDMA连接管理器（CM）是一个内核模块，负责管理RDMA连接的建立、维护和终止。它提供了一套API，使用户空间应用程序能够方便地使用RDMA技术进行高性能网络通信。

## 2 用户程序

我们使用rdmacm提供的示例程序`rdma_server.c`和`rdma_client.c`来演示RDMA CM的使用。核心的代码如下：

`rdma_server`的主要代码如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
int main(int argc, char **argv)
{
	...
	printf("rdma_server: start\n");
	ret = run();
	printf("rdma_server: end %d\n", ret);
	return ret;
}
static int run(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr qp_attr;
	struct ibv_wc wc;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = RAI_PASSIVE;
	hints.ai_port_space = RDMA_PS_TCP;
	// 获取地址信息
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) { ... }

	memset(&init_attr, 0, sizeof init_attr);
	// 设置QP属性
	init_attr.cap.max_send_wr = init_attr.cap.max_recv_wr = 1;
	init_attr.cap.max_send_sge = init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_inline_data = 16;
	init_attr.sq_sig_all = 1;
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 监听端口
	ret = rdma_listen(listen_id, 0);
	if (ret) { ... }
	// 获取连接请求
	ret = rdma_get_request(listen_id, &id);
	if (ret) { ... }

	memset(&qp_attr, 0, sizeof qp_attr);
	memset(&init_attr, 0, sizeof init_attr);
	// 查询QP属性
	ret = ibv_query_qp(id->qp, &qp_attr, IBV_QP_CAP, &init_attr);
	if (ret) { ... }
	if (init_attr.cap.max_inline_data >= 16)
		send_flags = IBV_SEND_INLINE;
	else
		printf("rdma_server: device doesn't support IBV_SEND_INLINE, " "using sge sends\n");

	// 注册接收消息缓冲区
	mr = rdma_reg_msgs(id, recv_msg, 16);
	if (!mr) { ... }
	if ((send_flags & IBV_SEND_INLINE) == 0) {
		// 注册发送消息缓冲区
		send_mr = rdma_reg_msgs(id, send_msg, 16);
		if (!send_mr) { ... }
	}
	// 提交接收请求
	ret = rdma_post_recv(id, NULL, recv_msg, 16, mr);
	if (ret) { ... }
	// 接受连接请求
	ret = rdma_accept(id, NULL);
	if (ret) { ... }
	// 获取接收完成事件
	while ((ret = rdma_get_recv_comp(id, &wc)) == 0);
	if (ret < 0) { ... }
	// 提交发送请求
	ret = rdma_post_send(id, NULL, send_msg, 16, send_mr, send_flags);
	if (ret) { ... }
	// 获取发送完成事件
	while ((ret = rdma_get_send_comp(id, &wc)) == 0);
	if (ret < 0)
		perror("rdma_get_send_comp");
	else
		ret = 0;

out_disconnect:
	// 断开连接
	rdma_disconnect(id);
out_dereg_send:
	// 注销发送消息缓冲区
	if ((send_flags & IBV_SEND_INLINE) == 0)
		rdma_dereg_mr(send_mr);
out_dereg_recv:
	// 注销接收消息缓冲区
	rdma_dereg_mr(mr);
out_destroy_accept_ep:
	// 销毁接受端点
	rdma_destroy_ep(id);
out_destroy_listen_ep:
	// 销毁监听端点
	rdma_destroy_ep(listen_id);
out_free_addrinfo:
	// 释放地址信息
	rdma_freeaddrinfo(res);
	return ret;
}
```

`rdma_client`的主要代码如下：

```c
// file: rdma-core/librdmacm/examples/rdma_client.c
int main(int argc, char **argv)
{
	...
	printf("rdma_client: start\n");
	ret = run();
	printf("rdma_client: end %d\n", ret);
	return ret;
}
static int run(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr attr;
	struct ibv_wc wc;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_TCP;
	// 获取地址信息
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) { ... }

	memset(&attr, 0, sizeof attr);
	// 设置QP属性
	attr.cap.max_send_wr = attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = 16;
	attr.qp_context = id;
	attr.sq_sig_all = 1;
	// 创建连接端点
	ret = rdma_create_ep(&id, res, NULL, &attr);
	if (attr.cap.max_inline_data >= 16)
		send_flags = IBV_SEND_INLINE;
	else
		printf("rdma_client: device doesn't support IBV_SEND_INLINE, using sge sends\n");
	...
	// 注册接收消息缓冲区
	mr = rdma_reg_msgs(id, recv_msg, 16);
	if (!mr) { ... }
	if ((send_flags & IBV_SEND_INLINE) == 0) {
		// 注册发送消息缓冲区
		send_mr = rdma_reg_msgs(id, send_msg, 16);
		if (!send_mr) { ... }
	}
	// 提交接收请求
	ret = rdma_post_recv(id, NULL, recv_msg, 16, mr);
	if (ret) { ... }
	// 连接到服务端
	ret = rdma_connect(id, NULL);
	if (ret) { ... }
	// 提交发送请求
	ret = rdma_post_send(id, NULL, send_msg, 16, send_mr, send_flags);
	if (ret) { ... }
	// 获取发送完成事件
	while ((ret = rdma_get_send_comp(id, &wc)) == 0);
	if (ret < 0) { ... }
	// 获取接收完成事件
	while ((ret = rdma_get_recv_comp(id, &wc)) == 0);
	if (ret < 0)
		perror("rdma_get_recv_comp");
	else
		ret = 0;

out_disconnect:
	rdma_disconnect(id);
out_dereg_send:
	if ((send_flags & IBV_SEND_INLINE) == 0)
		rdma_dereg_mr(send_mr);
out_dereg_recv:
	rdma_dereg_mr(mr);
out_destroy_ep:
	rdma_destroy_ep(id);
out_free_addrinfo:
	rdma_freeaddrinfo(res);
out:
	return ret;
}
```

编译后运行服务端和客户端，服务端运行结果如下：

```bash
$ ./rdma_server 
rdma_server: start
rdma_server: end 0
```

客户端运行结果如下：

```bash
$ ./rdma_client  -s 192.168.2.30
rdma_client: start
rdma_client: end 0
```

## 3 实现原理

通过`rdma_server`和`rdma_client`示例程序，我们可以看到RDMA CM的基本流程：

1. 服务端和客户端分别调用`rdma_getaddrinfo`函数获取地址信息；
2. 服务端和客户端分别调用`rdma_create_ep`函数创建连接端点；
3. 服务端调用`rdma_listen`函数监听指定端口；
4. 客户端调用`rdma_connect`函数连接到服务端；
5. 服务端调用`rdma_get_request`函数获取连接请求；
6. 服务端和客户端调用`rdma_post_recv`函数注册接收消息缓冲区，提交接收请求；
7. 服务端和客户端调用`rdma_post_send`函数注册发送消息缓冲区，提交发送请求；
8. 服务端和客户端调用`rdma_get_recv_comp`函数和`rdma_get_send_comp`函数获取完成事件，处理消息；
9. 服务端和客户端调用`rdma_disconnect`函数断开连接，调用`rdma_destroy_ep`函数销毁连接端点。

### 3.1 初始化UCMA

在`ucma_getaddrinfo`函数中，我们首先调用`ucma_init`函数初始化ucma模块，如下：

```c
// file: rdma-core/librdmacm/addrinfo.c
int rdma_getaddrinfo(const char *node, const char *service,
		     const struct rdma_addrinfo *hints, struct rdma_addrinfo **res)
{
	struct rdma_addrinfo *rai;
	int ret;
	// 检查参数是否为空
	if (!service && !node && !hints)
		return ERR(EINVAL);

	// 初始化UCMA
	ret = ucma_init();
	if (ret) return ret;
}
```

`ucma_init`用于初始化UCMA，包括检查ABI版本、同步设备列表、设置AF_IB支持等。如下：

```c
// file： rdma-core/librdmacm/cma.c
int ucma_init(void)
{
	int ret;
	// cma设备列表不为空时，直接返回0
	if (!list_empty(&cma_dev_list))
		return 0;

	pthread_mutex_lock(&mut);
	if (!list_empty(&cma_dev_list)) {
		pthread_mutex_unlock(&mut);
		return 0;
	}
	// 初始化idm_lock
	fastlock_init(&idm_lock);
	// 检查ABI版本
	ret = check_abi_version();
	if (ret) { ... }
	// 同步设备列表
	ret = sync_devices_list();
	if (ret) goto err1;
	// 设置AF_IB支持
	ucma_set_af_ib_support();
	pthread_mutex_unlock(&mut);
	return 0;
err1:
	fastlock_destroy(&idm_lock);
	pthread_mutex_unlock(&mut);
	return ret;
}
```

#### 3.1.1 检查ABI版本

`check_abi_version`函数通过netlink或sysfs检查ABI版本，确保与用户空间应用程序兼容。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int check_abi_version(void)
{
	if (abi_ver == -1) {
		// 通过netlink检查ABI版本
		if (check_abi_version_nl())
			// 如果netlink检查失败，通过sysfs检查ABI版本
			check_abi_version_sysfs();
	}
	// 检查ABI版本是否在有效范围内
	if (abi_ver < RDMA_USER_CM_MIN_ABI_VERSION ||
	    abi_ver > RDMA_USER_CM_MAX_ABI_VERSION)
		return -1;
	return 0;
}
```

#### 3.1.2 同步设备列表

`sync_devices_list`函数负责同步RDMA设备列表，确保用户空间应用程序能够访问到所有RDMA设备。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int sync_devices_list(void)
{
	struct ibv_device **new_list;
	int i, j, numb_dev;

	// 获取新的RDMA设备列表
	new_list = ibv_get_device_list(&numb_dev);
	if (!new_list) return ERR(ENODEV);

	if (!numb_dev) {
		// 如果新列表为空，释放内存并返回错误
		ibv_free_device_list(new_list);
		return ERR(ENODEV);
	}

	// 对新列表进行排序
	qsort(new_list, numb_dev, sizeof(struct ibv_device *), dev_cmp);
	if (unlikely(!dev_list)) {
		// 第一次同步，将新列表中的所有设备插入到设备列表中
		for (j = 0; new_list[j]; j++)
			insert_cma_dev(new_list[j]);
		goto out;
	}
	// 遍历旧列表和新列表，对比设备差异
	for (i = 0, j = 0; dev_list[i] || new_list[j];) {
		...
	}
	// 释放旧的设备列表
	ibv_free_device_list(dev_list);
out:
	dev_list = new_list;
	return 0;
}
```

`ibv_get_device_list`通过libibverbs库获取当前系统中的RDMA设备列表。

`insert_cma_dev`函数负责将新的RDMA设备插入到设备列表中。如下：

```c
// file: rdma-core/librdmacm/cma.c
static struct cma_device *insert_cma_dev(struct ibv_device *dev)
{
	struct cma_device *cma_dev, *p;
	// 分配内存
	cma_dev = calloc(1, sizeof(struct cma_device));
	if (!cma_dev) return NULL;

	// 初始化设备GUID和索引
	cma_dev->guid = ibv_get_device_guid(dev);
	cma_dev->ibv_idx = ibv_get_device_index(dev);
	cma_dev->dev = dev;

	// 遍历设备列表，按照ibv_idx和GUID排序
	list_for_each_rev(&cma_dev_list, p, entry) {
		if (cma_dev->ibv_idx == UCMA_INVALID_IB_INDEX) {
			if (be64toh(p->guid) < be64toh(cma_dev->guid)) break;
		} else {
			if (p->ibv_idx < cma_dev->ibv_idx) break;
		}
	}
	list_add_after(&cma_dev_list, &p->entry, &cma_dev->entry);
	return cma_dev;
}
```

#### 3.1.3 设置AF_IB支持

`ucma_set_af_ib_support`函数检查是否支持AF_IB地址族，通过创建一个RDMA CM ID并绑定到AF_IB地址来判断。如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_set_af_ib_support(void)
{
	struct rdma_cm_id *id;
	struct sockaddr_ib sib;
	int ret;
	// 创建RDMA CM ID
	ret = rdma_create_id(NULL, &id, NULL, RDMA_PS_IB);
	if (ret) return;

	memset(&sib, 0, sizeof sib);
	sib.sib_family = AF_IB;
	sib.sib_sid = htobe64(RDMA_IB_IP_PS_TCP);
	sib.sib_sid_mask = htobe64(RDMA_IB_IP_PS_MASK);
	af_ib_support = 1;
	// 绑定到AF_IB地址，判断是否成功
	ret = rdma_bind_addr(id, (struct sockaddr *) &sib);
	// 如果绑定成功，设置af_ib_support为1
	af_ib_support = !ret;

	rdma_destroy_id(id);
}
```

### 3.2 获取地址信息

`rdma_getaddrinfo`函数在初始化UCMA后，获取RDMA地址信息，函数如下：

```c
// file: rdma-core/librdmacm/addrinfo.c
int rdma_getaddrinfo(const char *node, const char *service,
		     const struct rdma_addrinfo *hints, struct rdma_addrinfo **res)
{
	struct rdma_addrinfo *rai;
	int ret;
	// 检查参数是否为空
	if (!service && !node && !hints)
		return ERR(EINVAL);

	// 初始化UCMA
	ret = ucma_init();
	if (ret) return ret;

	if (hints && hints->ai_flags & RAI_SA) {
		if (node || (hints->ai_flags & RAI_DNS)) return ERR(EOPNOTSUPP);
		// 获取地址信息
		return ucma_getaddrinfo_sa(service, res);
	}

	rai = calloc(1, sizeof(*rai));
	if (!rai)
		return ERR(ENOMEM);

	if (!hints) hints = &nohints;

	if (node || service) {
		// 获取地址信息
		ret = ucma_getaddrinfo(node, service, hints, rai);
	} else {
		// 复制hints中的地址信息
		rai->ai_flags = hints->ai_flags;
		rai->ai_family = hints->ai_family;
		rai->ai_qp_type = hints->ai_qp_type;
		rai->ai_port_space = hints->ai_port_space;
		if (hints->ai_dst_len) {
			ret = ucma_copy_addr(&rai->ai_dst_addr, &rai->ai_dst_len,
					     hints->ai_dst_addr, hints->ai_dst_len);
		}
	}
	if (ret)
		goto err;

	if (!rai->ai_src_len && hints->ai_src_len) {
		ret = ucma_copy_addr(&rai->ai_src_addr, &rai->ai_src_len,
				     hints->ai_src_addr, hints->ai_src_len);
		if (ret) goto err;
	}
	// 解析地址信息
	if (!(rai->ai_flags & RAI_PASSIVE))
		ucma_ib_resolve(&rai, hints);

	*res = rai;
	return 0;

err:
	rdma_freeaddrinfo(rai);
	return ret;
}
```

我们没有设置`RAI_SA`标记，使用`ucma_getaddrinfo`获取地址信息。如下：

```c
// file: rdma-core/librdmacm/addrinfo.c
static int ucma_getaddrinfo(const char *node, const char *service,
			    const struct rdma_addrinfo *hints, struct rdma_addrinfo *rai)
{
	struct addrinfo ai_hints;
	struct addrinfo *ai;
	int ret;

	if (hints != &nohints) {
		// 将rdma_addrinfo转换为addrinfo
		ucma_convert_to_ai(&ai_hints, hints);
		// 获取地址信息
		ret = getaddrinfo(node, service, &ai_hints, &ai);
	} else {
		ret = getaddrinfo(node, service, NULL, &ai);
	}
	if (ret) return ret;
	// 将addrinfo转换为rdma_addrinfo
	ret = ucma_convert_to_rai(rai, hints, ai);
	freeaddrinfo(ai);
	return ret;
}
```

`ucma_convert_to_rai`函数将`addrinfo`结构体转换为`rdma_addrinfo`结构体。如下：

```c
// file: rdma-core/librdmacm/addrinfo.c
static int ucma_convert_to_rai(struct rdma_addrinfo *rai,
			       const struct rdma_addrinfo *hints,
			       const struct addrinfo *ai)
{
	int ret;

	if (hints->ai_qp_type) {
		// 从hints中获取QP类型
		rai->ai_qp_type = hints->ai_qp_type;
	} else {
		// 根据socktype设置QP类型
		switch (ai->ai_socktype) {
		case SOCK_STREAM:
			rai->ai_qp_type = IBV_QPT_RC;
			break;
		case SOCK_DGRAM:
			rai->ai_qp_type = IBV_QPT_UD;
			break;
		}
	}

	if (hints->ai_port_space) {
		// 从hints中获取端口空间
		rai->ai_port_space = hints->ai_port_space;
	} else {
		// 根据协议设置端口空间
		switch (ai->ai_protocol) {
		case IPPROTO_TCP:
			rai->ai_port_space = RDMA_PS_TCP;
			break;
		case IPPROTO_UDP:
			rai->ai_port_space = RDMA_PS_UDP;
			break;
		}
	}

	if (ai->ai_flags & AI_PASSIVE) {
		// 设置RAI_PASSIVE标记
		rai->ai_flags = RAI_PASSIVE;
		// 解析源地址
		if (ai->ai_canonname)
			rai->ai_src_canonname = strdup(ai->ai_canonname);
		if ((hints->ai_flags & RAI_FAMILY) && (hints->ai_family == AF_IB) && (hints->ai_flags & RAI_NUMERICHOST)) {
			// 解析IB地址
			rai->ai_family = AF_IB;
			ret = ucma_convert_in6(rai->ai_port_space, 
						(struct sockaddr_ib **) &rai->ai_src_addr, &rai->ai_src_len,
					       (struct sockaddr_in6 *) ai->ai_addr, ai->ai_addrlen);
		} else {
			// 复制地址信息
			rai->ai_family = ai->ai_family;
			ret = ucma_copy_addr(&rai->ai_src_addr, &rai->ai_src_len, ai->ai_addr, ai->ai_addrlen);
		}
	} else {
		// 解析目的地址
		if (ai->ai_canonname)
			rai->ai_dst_canonname = strdup(ai->ai_canonname);

		if ((hints->ai_flags & RAI_FAMILY) && (hints->ai_family == AF_IB) && (hints->ai_flags & RAI_NUMERICHOST)) {
			rai->ai_family = AF_IB;
			ret = ucma_convert_in6(rai->ai_port_space,
					       (struct sockaddr_ib **) &rai->ai_dst_addr, &rai->ai_dst_len,
					       (struct sockaddr_in6 *) ai->ai_addr, ai->ai_addrlen);
		} else {
			rai->ai_family = ai->ai_family;
			ret = ucma_copy_addr(&rai->ai_dst_addr, &rai->ai_dst_len, ai->ai_addr, ai->ai_addrlen);
		}
	}
	return ret;
}
```

### 3.3 创建CM端点的过程

`rdma_create_ep`函数用于创建CM端点，函数如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_ep(struct rdma_cm_id **id, struct rdma_addrinfo *res,
		   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct rdma_cm_id *cm_id;
	struct cma_id_private *id_priv;
	int ret;

	// 创建CM ID
	ret = rdma_create_id2(NULL, &cm_id, NULL, res->ai_port_space, res->ai_qp_type);
	if (ret) return ret;

	if (res->ai_flags & RAI_PASSIVE) {
		// 创建被动EP，即：服务器端
		ret = ucma_passive_ep(cm_id, res, pd, qp_init_attr);
		if (ret) goto err;
		goto out;
	}

	if (af_ib_support)
		// 解析IB地址
		ret = rdma_resolve_addr2(cm_id, res->ai_src_addr, res->ai_src_len,
					 res->ai_dst_addr, res->ai_dst_len, 2000);
	else
		// 解析IP地址
		ret = rdma_resolve_addr(cm_id, res->ai_src_addr, res->ai_dst_addr, 2000);
	if (ret) goto err;

	if (res->ai_route_len) {
		ret = rdma_set_option(cm_id, RDMA_OPTION_IB, RDMA_OPTION_IB_PATH,
				      res->ai_route, res->ai_route_len);
		if (!ret) ret = ucma_complete(cm_id);
	} else {
		// 解析路由
		ret = rdma_resolve_route(cm_id, 2000);
	}
	if (ret) goto err;

	if (qp_init_attr) {
		// 创建QP
		qp_init_attr->qp_type = res->ai_qp_type;
		ret = rdma_create_qp(cm_id, pd, qp_init_attr);
		if (ret) goto err;
	}

	if (res->ai_connect_len) {
		id_priv = container_of(cm_id, struct cma_id_private, id);
		id_priv->connect = malloc(res->ai_connect_len);
		if (!id_priv->connect) {
			ret = ERR(ENOMEM);
			goto err;
		}
		// 复制连接信息
		memcpy(id_priv->connect, res->ai_connect, res->ai_connect_len);
		id_priv->connect_len = res->ai_connect_len;
	}
out:
	// 设置CM ID
	*id = cm_id;
	return 0;
err:
	rdma_destroy_ep(cm_id);
	return ret;
}
```

`ucma_passive_ep`函数用于创建被动EP，即：服务器端。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_passive_ep(struct rdma_cm_id *id, struct rdma_addrinfo *res,
			   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct cma_id_private *id_priv;
	int ret;

	if (af_ib_support)
		// 绑定IB地址
		ret = rdma_bind_addr2(id, res->ai_src_addr, res->ai_src_len);
	else
		// 绑定IP地址
		ret = rdma_bind_addr(id, res->ai_src_addr);
	if (ret) return ret;

	id_priv = container_of(id, struct cma_id_private, id);
	// 设置PD
	if (pd) id->pd = pd;

	if (qp_init_attr) {
		// 设置QP初始化属性
		id_priv->qp_init_attr = malloc(sizeof(*qp_init_attr));
		if (!id_priv->qp_init_attr) return ERR(ENOMEM);

		*id_priv->qp_init_attr = *qp_init_attr;
		id_priv->qp_init_attr->qp_type = res->ai_qp_type;
	}
	return 0;
}
```

接下来我们将逐步分析其各个步骤的实现过程。

### 3.4 创建事件通道

RDMA CM使用事件通道来通知用户空间应用程序发生的事件。我们可以通过`rdma_create_event_channel`函数创建事件通道，或者在创建CM ID时自动创建默认事件通道。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int rdma_create_id2(struct rdma_event_channel *channel,
			   struct rdma_cm_id **id, void *context,
			   enum rdma_port_space ps, enum ibv_qp_type qp_type)
{
	...
	ret = ucma_init();
	if (ret) return ret;

	id_priv = ucma_alloc_id(channel, context, ps, qp_type);
	if (!id_priv) return ERR(ENOMEM);
}
static struct cma_id_private *ucma_alloc_id(struct rdma_event_channel *channel,
					    void *context,
					    enum rdma_port_space ps,
					    enum ibv_qp_type qp_type)
{
	struct cma_id_private *id_priv;

	id_priv = calloc(1, sizeof(*id_priv));
	if (!id_priv) return NULL;

	...
	if (!channel) {
		// 创建默认事件通道
		id_priv->id.channel = rdma_create_event_channel();
		if (!id_priv->id.channel)
			goto err;
		id_priv->sync = 1;
	} else {
		// 设置CM ID的事件通道
		id_priv->id.channel = channel;
	}
	...
}
```

`rdma_create_event_channel`函数初始化ucma后，打开事件通道的文件描述符，如下：

```c
// file: rdma-core/librdmacm/cma.c
struct rdma_event_channel *rdma_create_event_channel(void)
{
	struct rdma_event_channel *channel;
	// 初始化ucma
	if (ucma_init()) return NULL;

	channel = malloc(sizeof(*channel));
	if (!channel) return NULL;
	// 打开事件通道的文件描述符
	channel->fd = open_cdev(dev_name, dev_cdev);
	if (channel->fd < 0) { goto err; }
	return channel;
err:
	free(channel);
	return NULL;
}
```

#### 3.4.1 打开事件通道

可以看到，事件通道通过打开字符设备文件来实现。`dev_name`是事件通道的设备名称，默认设置为`rdma_cm`，如下：

```c
// file: rdma-core/librdmacm/cma.c
static char dev_name[64] = "rdma_cm";
```

`open_cdev`函数负责打开字符设备文件，获取事件通道的文件描述符。如下：

```c
// file: rdma-core/util/open_cdev.c
int open_cdev(const char *devname_hint, dev_t cdev)
{
	char *devpath;
	int fd;
	// 构建字符设备文件路径
	if (asprintf(&devpath, RDMA_CDEV_DIR "/%s", devname_hint) < 0)
		return -1;
	// 内部打开字符设备文件
	fd = open_cdev_internal(devpath, cdev);
	free(devpath);
	if (fd == -1 && cdev != 0)
		// 如果失败，尝试使用robust方式打开
		return open_cdev_robust(devname_hint, cdev);
	return fd;
}
```

#### 3.4.2 `rdma_cm`文件介绍

`rdma_cm`是RDMA核心模块中的字符设备文件，用于用户空间与内核空间进行通信。在`ucma`模块中注册，如下：

```c
// file: drivers/infiniband/core/ucma.c
static int __init ucma_init(void)
{
	int ret;
	// 注册ucma misc设备
	ret = misc_register(&ucma_misc);
	if (ret) return ret;

	// 创建abi_version属性文件
	ret = device_create_file(ucma_misc.this_device, &dev_attr_abi_version);
	if (ret) {
		pr_err("rdma_ucm: couldn't create abi_version attr\n");
		goto err1;
	}
	// 创建sysctl路径
	ucma_ctl_table_hdr = register_net_sysctl(&init_net, "net/rdma_ucm", ucma_ctl_table);
	if (!ucma_ctl_table_hdr) { ... }

	// 注册rdma_cma_client客户端
	ret = ib_register_client(&rdma_cma_client);
	if (ret) goto err3;

	return 0;
err3:
	unregister_net_sysctl_table(ucma_ctl_table_hdr);
err2:
	device_remove_file(ucma_misc.this_device, &dev_attr_abi_version);
err1:
	misc_deregister(&ucma_misc);
	return ret;
}
static void __exit ucma_cleanup(void)
{
	ib_unregister_client(&rdma_cma_client);
	unregister_net_sysctl_table(ucma_ctl_table_hdr);
	device_remove_file(ucma_misc.this_device, &dev_attr_abi_version);
	misc_deregister(&ucma_misc);
}
module_init(ucma_init);
module_exit(ucma_cleanup);
```

`ucma_misc`是`ucma`模块注册的misc设备，其定义如下：

```c
// file: drivers/infiniband/core/ucma.c
static struct miscdevice ucma_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "rdma_cm",
	.nodename	= "infiniband/rdma_cm",
	.mode		= 0666,
	.fops		= &ucma_fops,
};
```

设置的文件操作接口为`ucma_fops`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static const struct file_operations ucma_fops = {
	.owner 	 = THIS_MODULE,
	.open 	 = ucma_open,
	.release = ucma_close,
	.write	 = ucma_write,
	.poll    = ucma_poll,
};
```

用户空间通过写入事件通道文件描述符与内核空间进行通信，`rdma_cm`文件设置的`.write`接口为`ucma_write`，其实现如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_write(struct file *filp, const char __user *buf,
			  size_t len, loff_t *pos)
{
	struct ucma_file *file = filp->private_data;
	struct rdma_ucm_cmd_hdr hdr;
	ssize_t ret;

	if (!ib_safe_file_access(filp)) { ... }
	if (len < sizeof(hdr)) return -EINVAL;

	// 从用户空间复制命令头
	if (copy_from_user(&hdr, buf, sizeof(hdr))) return -EFAULT;

	// 检查命令是否存在
	if (hdr.cmd >= ARRAY_SIZE(ucma_cmd_table)) return -EINVAL;
	hdr.cmd = array_index_nospec(hdr.cmd, ARRAY_SIZE(ucma_cmd_table));

	if (hdr.in + sizeof(hdr) > len) return -EINVAL;
	if (!ucma_cmd_table[hdr.cmd]) return -ENOSYS;
	// 执行命令处理函数
	ret = ucma_cmd_table[hdr.cmd](file, buf + sizeof(hdr), hdr.in, hdr.out);
	if (!ret) ret = len;

	return ret;
}
```

`struct rdma_ucm_cmd_hdr`结构定义了用户空间和内核空间之间通信的命令头，包含命令ID、输入/输出参数长度等字段。如下：

```c
// file: include/uapi/rdma/rdma_user_cm.h
struct rdma_ucm_cmd_hdr {
	__u32 cmd;
	__u16 in;
	__u16 out;
};
```

`ucma_cmd_table`定义了内核空间处理用户空间命令的函数指针数组，每个元素对应一个命令ID。如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t (*ucma_cmd_table[])(struct ucma_file *file,
				   const char __user *inbuf,
				   int in_len, int out_len) = {
	[RDMA_USER_CM_CMD_CREATE_ID] 	 = ucma_create_id,
	[RDMA_USER_CM_CMD_DESTROY_ID]	 = ucma_destroy_id,
	...
};
```

后续我们将分析每个命令的处理过程。

### 3.5 创建CM ID

我们可以使用`rdma_create_id`函数或`rdma_create_id2`函数创建CM ID。如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_ep(struct rdma_cm_id **id, struct rdma_addrinfo *res,
		   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct rdma_cm_id *cm_id;
	struct cma_id_private *id_priv;
	int ret;

	// 创建CM ID
	ret = rdma_create_id2(NULL, &cm_id, NULL, res->ai_port_space, res->ai_qp_type);
	if (ret) return ret;
	...
}
```

`rdma_create_id`函数将根据端口空间选择QP类型，调用`rdma_create_id2`函数创建CM ID。如下:

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_id(struct rdma_event_channel *channel,
		   struct rdma_cm_id **id, void *context,
		   enum rdma_port_space ps)
{
	enum ibv_qp_type qp_type;
	// 根据端口空间选择QP类型
	qp_type = (ps == RDMA_PS_IPOIB || ps == RDMA_PS_UDP) ? IBV_QPT_UD : IBV_QPT_RC;
	// 创建CM ID
	return rdma_create_id2(channel, id, context, ps, qp_type);
}
```

#### 3.5.1 用户空间创建CM ID

`rdma_create_id2`函数负责创建CM ID，并将其与事件通道关联。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int rdma_create_id2(struct rdma_event_channel *channel,
			   struct rdma_cm_id **id, void *context,
			   enum rdma_port_space ps, enum ibv_qp_type qp_type)
{
	struct ucma_abi_create_id_resp resp;
	struct ucma_abi_create_id cmd;
	struct cma_id_private *id_priv;
	int ret;

	// 初始化ucma
	ret = ucma_init();
	if (ret) return ret;

	// 分配CM ID私有结构体
	id_priv = ucma_alloc_id(channel, context, ps, qp_type);
	if (!id_priv) return ERR(ENOMEM);

	// 初始化`CREATE_ID`指令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, CREATE_ID, &resp, sizeof resp);
	cmd.uid = (uintptr_t) id_priv;
	cmd.ps = ps;
	cmd.qp_type = qp_type;

	// 通过写入事件通道文件描述符发送创建ID命令
	ret = write(id_priv->id.channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof(cmd)) {
		ret = (ret >= 0) ? ERR(ENODATA) : -1;
		goto err;
	}

	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);
	// 获取CM ID句柄后，插入ID列表
	id_priv->handle = resp.id;
	ucma_insert_id(id_priv);
	*id = &id_priv->id;
	return 0;

err:	ucma_free_id(id_priv);
	return ret;
}
```

`ucma_alloc_id`函数负责分配CM ID私有结构体，初始化CM ID结构体，设置上下文、端口空间和QP类型。如下：

```c
// file: rdma-core/librdmacm/cma.c
static struct cma_id_private *ucma_alloc_id(struct rdma_event_channel *channel,
					    void *context,
					    enum rdma_port_space ps,
					    enum ibv_qp_type qp_type)
{
	struct cma_id_private *id_priv;
	// 分配CM ID私有结构体内存
	id_priv = calloc(1, sizeof(*id_priv));
	if (!id_priv) return NULL;

	// 初始化CM ID结构体
	id_priv->id.context = context;
	id_priv->id.ps = ps;
	id_priv->id.qp_type = qp_type;
	id_priv->handle = 0xFFFFFFFF;

	// 创建事件通道
	if (!channel) {
		id_priv->id.channel = rdma_create_event_channel();
		if (!id_priv->id.channel) goto err;
		id_priv->sync = 1;
	} else {
		id_priv->id.channel = channel;
	}
	// 初始化互斥锁和条件变量
	pthread_mutex_init(&id_priv->mut, NULL);
	if (pthread_cond_init(&id_priv->cond, NULL))
		goto err;
	return id_priv;

err:	ucma_free_id(id_priv);
	return NULL;
}
```

#### 3.5.2 内核空间处理创建ID命令

`CREATE_ID`对应的处理函数为`ucma_create_id`。如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_create_id(struct ucma_file *file, const char __user *inbuf,
			      int in_len, int out_len)
{
	struct rdma_ucm_create_id cmd;
	struct rdma_ucm_create_id_resp resp;
	struct ucma_context *ctx;
	struct rdma_cm_id *cm_id;
	enum ib_qp_type qp_type;
	int ret;

	if (out_len < sizeof(resp)) return -ENOSPC;
	// 从用户空间复制创建ID命令
	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) return -EFAULT;

	// 获取QP类型
	ret = ucma_get_qp_type(&cmd, &qp_type);
	if (ret) return ret;
	// 分配上下文
	ctx = ucma_alloc_ctx(file);
	if (!ctx) return -ENOMEM;

	ctx->uid = cmd.uid;
	// 创建CM ID
	cm_id = rdma_create_user_id(ucma_event_handler, ctx, cmd.ps, qp_type);
	if (IS_ERR(cm_id)) { ... }
	// 设置上下文的CM ID
	ucma_set_ctx_cm_id(ctx, cm_id);

	resp.id = ctx->id;
	// 复制响应到用户空间
	if (copy_to_user(u64_to_user_ptr(cmd.response), &resp, sizeof(resp))) { ... }

	mutex_lock(&file->mut);
	// 完成上下文
	ucma_finish_ctx(ctx);
	mutex_unlock(&file->mut);
	return 0;

err1:
	ucma_destroy_private_ctx(ctx);
	return ret;
}
```

##### 1. 端口空间和QP类型映射

`ucma_get_qp_type`函数负责根据端口空间选择QP类型。如下：

```c
// file: drivers/infiniband/core/ucma.c
static int ucma_get_qp_type(struct rdma_ucm_create_id *cmd, enum ib_qp_type *qp_type)
{
	switch (cmd->ps) {
	case RDMA_PS_TCP:
		// TCP端口空间使用RC QP类型
		*qp_type = IB_QPT_RC;
		return 0;
	case RDMA_PS_UDP:
	case RDMA_PS_IPOIB:
		// UDP和IPOIB端口空间使用UD QP类型
		*qp_type = IB_QPT_UD;
		return 0;
	case RDMA_PS_IB:
		// IB端口空间使用用户指定的QP类型
		*qp_type = cmd->qp_type;
		return 0;
	default:
		return -EINVAL;
	}
}
```

##### 2. 创建CM ID

`rdma_create_user_id`函数调用`__rdma_create_id`创建CM ID，如下：

```c
// file: drivers/infiniband/core/cma.c
struct rdma_cm_id *rdma_create_user_id(rdma_cm_event_handler event_handler,
				       void *context,
				       enum rdma_ucm_port_space ps,
				       enum ib_qp_type qp_type)
{
	struct rdma_id_private *ret;
	// 创建CM ID
	ret = __rdma_create_id(current->nsproxy->net_ns, event_handler, context,
			       ps, qp_type, NULL);
	if (IS_ERR(ret)) return ERR_CAST(ret);
	// 设置CM ID名称为空
	rdma_restrack_set_name(&ret->res, NULL);
	return &ret->id;
}
```

`__rdma_create_id`函数负责创建CM ID，如下：

```c
// file: drivers/infiniband/core/cma.c
static struct rdma_id_private *
__rdma_create_id(struct net *net, rdma_cm_event_handler event_handler,
		 void *context, enum rdma_ucm_port_space ps,
		 enum ib_qp_type qp_type, const struct rdma_id_private *parent)
{
	struct rdma_id_private *id_priv;
	// 分配CM ID私有结构体内存
	id_priv = kzalloc_obj(*id_priv);
	if (!id_priv) return ERR_PTR(-ENOMEM);

	// 初始化CM ID结构体
	id_priv->state = RDMA_CM_IDLE;
	id_priv->restricted_node_type = RDMA_NODE_UNSPECIFIED;
	id_priv->id.context = context;
	id_priv->id.event_handler = event_handler;
	id_priv->id.ps = ps;
	id_priv->id.qp_type = qp_type;
	id_priv->tos_set = false;
	id_priv->timeout_set = false;
	id_priv->min_rnr_timer_set = false;
	id_priv->gid_type = IB_GID_TYPE_IB;
	spin_lock_init(&id_priv->lock);
	mutex_init(&id_priv->qp_mutex);
	init_completion(&id_priv->comp);
	refcount_set(&id_priv->refcount, 1);
	mutex_init(&id_priv->handler_mutex);
	INIT_LIST_HEAD(&id_priv->device_item);
	INIT_LIST_HEAD(&id_priv->id_list_entry);
	INIT_LIST_HEAD(&id_priv->listen_list);
	INIT_LIST_HEAD(&id_priv->mc_list);
	// 生成随机序列号
	get_random_bytes(&id_priv->seq_num, sizeof id_priv->seq_num);
	id_priv->id.route.addr.dev_addr.net = get_net(net);
	id_priv->seq_num &= 0x00ffffff;
	// 初始化网络事件工作
	INIT_WORK(&id_priv->id.net_work, cma_netevent_work_handler);
	
	// 初始化资源跟踪
	rdma_restrack_new(&id_priv->res, RDMA_RESTRACK_CM_ID);
	if (parent)
		rdma_restrack_parent_name(&id_priv->res, &parent->res);

	return id_priv;
}
```

### 3.6 CM BIND

我们在创建服务端的端点时，通过`ucma_passive_ep`函数创建被动端点，进行地址绑定。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_passive_ep(struct rdma_cm_id *id, struct rdma_addrinfo *res,
			   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct cma_id_private *id_priv;
	int ret;

	if (af_ib_support)
		// 绑定IB地址
		ret = rdma_bind_addr2(id, res->ai_src_addr, res->ai_src_len);
	else
		// 绑定IP地址
		ret = rdma_bind_addr(id, res->ai_src_addr);
	if (ret) return ret;

	id_priv = container_of(id, struct cma_id_private, id);
	// 设置PD
	if (pd) id->pd = pd;

	if (qp_init_attr) {
		// 设置QP初始化属性
		id_priv->qp_init_attr = malloc(sizeof(*qp_init_attr));
		if (!id_priv->qp_init_attr) return ERR(ENOMEM);

		*id_priv->qp_init_attr = *qp_init_attr;
		id_priv->qp_init_attr->qp_type = res->ai_qp_type;
	}
	return 0;
}
```

#### 3.6.1 用户空间BIND

`rdma_bind_addr`通过`BIND`(支持AF_IB的情况下)或`BIND_IP`命令和内核空间进行交互。 我们以`BIND_IP`为例，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct ucma_abi_bind_ip cmd;
	struct cma_id_private *id_priv;
	int ret, addrlen;
	// 获取地址的长度
	addrlen = ucma_addrlen(addr);
	if (!addrlen) return ERR(EINVAL);

	if (af_ib_support)
		// 支持AF_IB的情况下
		return rdma_bind_addr2(id, addr, addrlen);

	// 初始化`BIND_IP`指令
	CMA_INIT_CMD(&cmd, sizeof cmd, BIND_IP);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;
	memcpy(&cmd.addr, addr, addrlen);

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) return (ret >= 0) ? ERR(ENODATA) : -1;
	// 正常绑定后获取路由
	return ucma_query_route(id);
}
```

#### 3.6.2 内核空间处理BIND

`BIND_IP`对应的处理函数为`ucma_bind_ip`。如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_bind_ip(struct ucma_file *file, const char __user *inbuf,
			      int in_len, int out_len)
{
	struct rdma_ucm_bind_ip cmd;
	struct ucma_context *ctx;
	int ret;

	// 复制用户空间命令
	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) return -EFAULT;
	// 检查用户设置的地址
	if (!rdma_addr_size_in6(&cmd.addr)) return -EINVAL;
	// 获取`ucma_context`
	ctx = ucma_get_ctx(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	mutex_lock(&ctx->mutex);
	// 绑定地址
	ret = rdma_bind_addr(ctx->cm_id, (struct sockaddr *) &cmd.addr);
	mutex_unlock(&ctx->mutex);

	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_bind_addr`进行实际的绑定操作，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	// 绑定目的地址
	return rdma_bind_addr_dst(id_priv, addr, cma_dst_addr(id_priv));
}
```

`cma_dst_addr`获取`cm_id`的目的地址，如下：

```c
// file: drivers/infiniband/core/cma.c
static inline struct sockaddr *cma_dst_addr(struct rdma_id_private *id_priv)
{
	return (struct sockaddr *)&id_priv->id.route.addr.dst_addr;
}
```

`rdma_bind_addr_dst`函数绑定`cm_id`地址信息，如下：

```c
// file: drivers/infiniband/core/cma.c
static int rdma_bind_addr_dst(struct rdma_id_private *id_priv,
			      struct sockaddr *addr, const struct sockaddr *daddr)
{
	struct sockaddr *id_daddr;
	int ret;
	// 检查网络家族
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6 &&
	    addr->sa_family != AF_IB)
		return -EAFNOSUPPORT;
	// 修改状态为`RDMA_CM_ADDR_BOUND`
	if (!cma_comp_exch(id_priv, RDMA_CM_IDLE, RDMA_CM_ADDR_BOUND))
		return -EINVAL;

	// 本地IPv6地址检查
	ret = cma_check_linklocal(&id_priv->id.route.addr.dev_addr, addr);
	if (ret) goto err1;

	// 复制addr到源地址
	memcpy(cma_src_addr(id_priv), addr, rdma_addr_size(addr));
	if (!cma_any_addr(addr)) {
		// 转换设备地址，根据源地址获取网卡信息
		ret = cma_translate_addr(addr, &id_priv->id.route.addr.dev_addr);
		if (ret) goto err1;
		// 根据源地址获取CM设备,端口，gid等属性
		ret = cma_acquire_dev_by_src_ip(id_priv);
		if (ret) goto err1;
	}

	// AFONLY选项检查
	if (!(id_priv->options & (1 << CMA_OPTION_AFONLY))) {
		if (addr->sa_family == AF_INET)
			id_priv->afonly = 1;
#if IS_ENABLED(CONFIG_IPV6)
		else if (addr->sa_family == AF_INET6) {
			struct net *net = id_priv->id.route.addr.dev_addr.net;
			id_priv->afonly = net->ipv6.sysctl.bindv6only;
		}
#endif
	}
	// 目的地址检查
	id_daddr = cma_dst_addr(id_priv);
	if (daddr != id_daddr)
		memcpy(id_daddr, daddr, rdma_addr_size(addr));
	id_daddr->sa_family = addr->sa_family;

	// 获取端口
	ret = cma_get_port(id_priv);
	if (ret) goto err2;

	if (!cma_any_addr(addr))
		// RDMA添加追踪资源
		rdma_restrack_add(&id_priv->res);
	return 0;
err2:
	if (id_priv->cma_dev)
		cma_release_dev(id_priv);
err1:
	cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_IDLE);
	return ret;
}
```

##### 1. 转换绑定地址

`cma_translate_addr`函数转换IP或IB地址，我们使用IP地址，通过调用`rdma_translate_ip`进行状态，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_translate_addr(struct sockaddr *addr, struct rdma_dev_addr *dev_addr)
{
	int ret;
	if (addr->sa_family != AF_IB) {
		// 转换IP地址
		ret = rdma_translate_ip(addr, dev_addr);
	} else {
		// 转换IB地址
		cma_translate_ib((struct sockaddr_ib *) addr, dev_addr);
		ret = 0;
	}
	return ret;
}
```

`rdma_translate_ip`通过网卡设备索引或IP地址获取网卡设备后，复制L2地址信息，如下：

```c
// file: drivers/infiniband/core/addr.c
int rdma_translate_ip(const struct sockaddr *addr, struct rdma_dev_addr *dev_addr)
{
	struct net_device *dev;

	if (dev_addr->bound_dev_if) {
		// 通过if获取网卡设备
		dev = dev_get_by_index(dev_addr->net, dev_addr->bound_dev_if);
		if (!dev) return -ENODEV;
		rdma_copy_src_l2_addr(dev_addr, dev);
		dev_put(dev);
		return 0;
	}
	rcu_read_lock();
	// 通过IP地址获取网卡设备
	dev = rdma_find_ndev_for_src_ip_rcu(dev_addr->net, addr);
	if (!IS_ERR(dev)) rdma_copy_src_l2_addr(dev_addr, dev);
	rcu_read_unlock();
	return PTR_ERR_OR_ZERO(dev);
}
```

`rdma_copy_src_l2_addr`复制网卡的L2信息，如下：

```c
// file: drivers/infiniband/core/addr.c
void rdma_copy_src_l2_addr(struct rdma_dev_addr *dev_addr,
			   const struct net_device *dev)
{
	dev_addr->dev_type = dev->type;
	memcpy(dev_addr->src_dev_addr, dev->dev_addr, MAX_ADDR_LEN);
	memcpy(dev_addr->broadcast, dev->broadcast, MAX_ADDR_LEN);
	dev_addr->bound_dev_if = dev->ifindex;
}
```

##### 2. 绑定CM

`cma_acquire_dev_by_src_ip`函数获取CMA设备，端口，gid等属性后，和CM ID绑定，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_acquire_dev_by_src_ip(struct rdma_id_private *id_priv)
{
	struct rdma_dev_addr *dev_addr = &id_priv->id.route.addr.dev_addr;
	const struct ib_gid_attr *sgid_attr;
	union ib_gid gid, iboe_gid, *gidp;
	struct cma_device *cma_dev;
	enum ib_gid_type gid_type;
	int ret = -ENODEV;
	u32 port;

	if (dev_addr->dev_type != ARPHRD_INFINIBAND && id_priv->id.ps == RDMA_PS_IPOIB)
		return -EINVAL;

	// IP地址转换为gid
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr, &iboe_gid);
	// 复制到gid
	memcpy(&gid, dev_addr->src_dev_addr + rdma_addr_gid_offset(dev_addr), sizeof(gid));

	mutex_lock(&lock);
	list_for_each_entry(cma_dev, &dev_list, list) {
		rdma_for_each_port (cma_dev->device, port) {
			// 遍历所有设备的所有端口
			gidp = rdma_protocol_roce(cma_dev->device, port) ? &iboe_gid : &gid;
			gid_type = cma_dev->default_gid_type[port - 1];
			// 验证端口
			sgid_attr = cma_validate_port(cma_dev->device, port, gid_type, gidp, id_priv);
			if (!IS_ERR(sgid_attr)) {
				// 端口匹配时，绑定端口和属性
				id_priv->id.port_num = port;
				cma_bind_sgid_attr(id_priv, sgid_attr);
				// 将cm id添加到cma设备中，完成绑定
				cma_attach_to_dev(id_priv, cma_dev);
				ret = 0;
				goto out;
			}
		}
	}
out:
	mutex_unlock(&lock);
	return ret;
}
```

`cma_attach_to_dev`将cm id和cma设备绑定，如下：

```c
// file: drivers/infiniband/core/cma.c
static void cma_attach_to_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	_cma_attach_to_dev(id_priv, cma_dev);
	id_priv->gid_type =
		cma_dev->default_gid_type[id_priv->id.port_num - rdma_start_port(cma_dev->device)];
}
static void _cma_attach_to_dev(struct rdma_id_private *id_priv, struct cma_device *cma_dev)
{
	cma_dev_get(cma_dev);
	// 设置cm id属性
	id_priv->cma_dev = cma_dev;
	id_priv->id.device = cma_dev->device;
	id_priv->id.route.addr.dev_addr.transport =
		rdma_node_get_transport(cma_dev->device->node_type);
	// 添加到cma设备列表中
	list_add_tail(&id_priv->device_item, &cma_dev->id_list);

	trace_cm_id_attach(id_priv, cma_dev->device);
}
```

##### 3. 绑定端口

`cma_get_port`获取端口后绑定到cm id，如下： 

```c
// file: drivers/infiniband/core/cma.c
static int cma_get_port(struct rdma_id_private *id_priv)
{
	enum rdma_ucm_port_space ps;
	int ret;

	if (cma_family(id_priv) != AF_IB)
		ps = cma_select_inet_ps(id_priv);
	else
		ps = cma_select_ib_ps(id_priv);
	if (!ps) return -EPROTONOSUPPORT;

	mutex_lock(&lock);
	if (cma_any_port(cma_src_addr(id_priv)))
		// 分配任意端口
		ret = cma_alloc_any_port(ps, id_priv);
	else
		// 使用指定端口
		ret = cma_use_port(ps, id_priv);
	mutex_unlock(&lock);
	return ret;
}
```

`cma_alloc_any_port`获取一个没有使用的端口后绑定到cm id，绑定过程和`cma_use_port`相同。我们分析`cma_use_port`，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_use_port(enum rdma_ucm_port_space ps, struct rdma_id_private *id_priv)
{
	struct rdma_bind_list *bind_list;
	unsigned short snum;
	int ret;

	lockdep_assert_held(&lock);
	// 获取端口号
	snum = ntohs(cma_port(cma_src_addr(id_priv)));
	if (snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;
	// 查找端口绑定列表
	bind_list = cma_ps_find(id_priv->id.route.addr.dev_addr.net, ps, snum);
	if (!bind_list) {
		// 端口未绑定，分配端口
		ret = cma_alloc_port(ps, id_priv, snum);
	} else {
		// 端口已绑定，检查端口是否可用
		ret = cma_check_port(bind_list, id_priv, id_priv->reuseaddr);
		if (!ret)
			// 端口可用，绑定端口
			cma_bind_port(bind_list, id_priv);
	}
	return ret;
}
```

在不存在绑定列表时，调用`cma_alloc_port`分配端口。如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_alloc_port(enum rdma_ucm_port_space ps,
			  struct rdma_id_private *id_priv, unsigned short snum)
{
	struct rdma_bind_list *bind_list;
	int ret;

	lockdep_assert_held(&lock);
	// 分配绑定列表内存
	bind_list = kzalloc_obj(*bind_list);
	if (!bind_list) return -ENOMEM;

	// 分配端口
	ret = cma_ps_alloc(id_priv->id.route.addr.dev_addr.net, ps, bind_list, snum);
	if (ret < 0) goto err;

	// 设置端口属性
	bind_list->ps = ps;
	bind_list->port = snum;
	// 绑定端口
	cma_bind_port(bind_list, id_priv);
	return 0;
err:
	kfree(bind_list);
	return ret == -ENOSPC ? -EADDRNOTAVAIL : ret;
}
```

`cma_bind_port`将端口绑定到cm id，如下：

```c
// file: drivers/infiniband/core/cma.c
static void cma_bind_port(struct rdma_bind_list *bind_list, struct rdma_id_private *id_priv)
{
	struct sockaddr *addr;
	struct sockaddr_ib *sib;
	u64 sid, mask;
	__be16 port;

	lockdep_assert_held(&lock);
	// 获取cm id的源地址
	addr = cma_src_addr(id_priv);
	port = htons(bind_list->port);

	switch (addr->sa_family) {
	case AF_INET:
		// 设置IPv4端口号
		((struct sockaddr_in *) addr)->sin_port = port;
		break;
	case AF_INET6:
		// 设置IPv6端口号
		((struct sockaddr_in6 *) addr)->sin6_port = port;
		break;
	case AF_IB:
		// 设置IB端口号
		sib = (struct sockaddr_ib *) addr;
		sid = be64_to_cpu(sib->sib_sid);
		mask = be64_to_cpu(sib->sib_sid_mask);
		sib->sib_sid = cpu_to_be64((sid & mask) | (u64) ntohs(port));
		sib->sib_sid_mask = cpu_to_be64(~0ULL);
		break;
	}
	id_priv->bind_list = bind_list;
	// 将cm id添加到绑定列表中
	hlist_add_head(&id_priv->node, &bind_list->owners);
}
```

### 3.7 CM RESOLVE_ADDR

在创建CM ID后，我们可以通过`rdma_resolve_addr`函数解析IP地址，或者通过`rdma_resolve_addr2`函数解析IB地址，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_ep(struct rdma_cm_id **id, struct rdma_addrinfo *res,
		   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct rdma_cm_id *cm_id;
	struct cma_id_private *id_priv;
	int ret;
	...

	if (af_ib_support)
		ret = rdma_resolve_addr2(cm_id, res->ai_src_addr, res->ai_src_len,
					 res->ai_dst_addr, res->ai_dst_len, 2000);
	else
		ret = rdma_resolve_addr(cm_id, res->ai_src_addr, res->ai_dst_addr, 2000);
	if (ret) goto err;
}
```

#### 3.7.1 用户空间RESOLVE_IP

`rdma_resolve_addr`通过`RESOLVE_IP`命令解析IP地址，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms)
{
	struct ucma_abi_resolve_ip cmd;
	struct cma_id_private *id_priv;
	int ret, dst_len, src_len;
	// 获取目标地址长度
	dst_len = ucma_addrlen(dst_addr);
	if (!dst_len) return ERR(EINVAL);
	// 获取源地址长度
	src_len = ucma_addrlen(src_addr);
	if (src_addr && !src_len) return ERR(EINVAL);

	if (af_ib_support)
		// 解析IB地址
		return rdma_resolve_addr2(id, src_addr, src_len, dst_addr, dst_len, timeout_ms);

	// 生成`RESOLVE_IP`命令
	CMA_INIT_CMD(&cmd, sizeof cmd, RESOLVE_IP);
	id_priv = container_of(id, struct cma_id_private, id);
	// 设置cmd参数
	cmd.id = id_priv->handle;
	if (src_addr)
		memcpy(&cmd.src_addr, src_addr, src_len);
	memcpy(&cmd.dst_addr, dst_addr, dst_len);
	cmd.timeout_ms = timeout_ms;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;
	// 复制解析后的目标地址到cm id路由地址中
	memcpy(&id->route.addr.dst_storage, dst_addr, dst_len);
	// 完成ucma事件
	return ucma_complete(id);
}
```

或者使用`rdma_resolve_addr2`函数解析IB地址。如下：

```c
// file: rdma-core/librdmacm/cma.c
static int rdma_resolve_addr2(struct rdma_cm_id *id, struct sockaddr *src_addr,
			      socklen_t src_len, struct sockaddr *dst_addr,
			      socklen_t dst_len, int timeout_ms)
{
	struct ucma_abi_resolve_addr cmd;
	struct cma_id_private *id_priv;
	int ret;
	// 初始化`RESOLVE_ADDR`命令
	CMA_INIT_CMD(&cmd, sizeof cmd, RESOLVE_ADDR);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;
	cmd.src_size = src_len;
	memcpy(&cmd.src_addr, src_addr, src_len);
	memcpy(&cmd.dst_addr, dst_addr, dst_len);
	cmd.dst_size = dst_len;
	cmd.timeout_ms = timeout_ms;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;
	// 设置解析后的目标地址到cm id路由地址中
	memcpy(&id->route.addr.dst_addr, dst_addr, dst_len);
	return ucma_complete(id);
}
```

#### 3.7.2 内核空间处理RESOLVE_IP

`RESOLVE_IP`命令用于解析IP地址，对应的处理函数为`ucma_resolve_ip`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_resolve_ip(struct ucma_file *file,
			       const char __user *inbuf, int in_len, int out_len)
{
	struct rdma_ucm_resolve_ip cmd;
	struct ucma_context *ctx;
	int ret;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;
	// 验证源地址和目标地址长度是否正确
	if ((cmd.src_addr.sin6_family && !rdma_addr_size_in6(&cmd.src_addr)) ||
	    !rdma_addr_size_in6(&cmd.dst_addr))
		return -EINVAL;

	ctx = ucma_get_ctx(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	mutex_lock(&ctx->mutex);
	// 解析IP地址
	ret = rdma_resolve_addr(ctx->cm_id, (struct sockaddr *) &cmd.src_addr,
				(struct sockaddr *) &cmd.dst_addr, cmd.timeout_ms);
	mutex_unlock(&ctx->mutex);
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_resolve_addr`根据地址类型解析IP地址或IB地址。如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr, unsigned long timeout_ms)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	int ret;
	// 解析源地址，解析绑定的源地址，并设置状态为`RDMA_CM_ADDR_BOUND`
	ret = resolve_prepare_src(id_priv, src_addr, dst_addr);
	if (ret) return ret;

	if (cma_any_addr(dst_addr)) {
		// 解析环回地址
		ret = cma_resolve_loopback(id_priv);
	} else {
		if (dst_addr->sa_family == AF_IB) {
			// 解析IB地址
			ret = cma_resolve_ib_addr(id_priv);
		} else {
			if (id_priv->used_resolve_ip)
				rdma_addr_cancel(&id->route.addr.dev_addr);
			else
				id_priv->used_resolve_ip = 1;
			// 解析IP地址
			ret = rdma_resolve_ip(cma_src_addr(id_priv), dst_addr, &id->route.addr.dev_addr,
					      timeout_ms, addr_handler, false, id_priv);
		}
	}
	if (ret) goto err;
	return 0;
err:
	cma_comp_exch(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_BOUND);
	return ret;
}
```

##### 1. 解析环回地址

`cma_resolve_loopback`解析环回地址，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_resolve_loopback(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	union ib_gid gid;
	int ret;

	work = kzalloc_obj(*work);
	if (!work) return -ENOMEM;

	if (!id_priv->cma_dev) {
		// 没有绑定的设备时，绑定环回设备
		ret = cma_bind_loopback(id_priv);
		if (ret) goto err;
	}
	// 获取源地址的SGID，并设置为目标地址的DGID
	rdma_addr_get_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	rdma_addr_set_dgid(&id_priv->id.route.addr.dev_addr, &gid);
	// 添加work到wq队列
	enqueue_resolve_addr_work(work, id_priv);
	return 0;
err:
	kfree(work);
	return ret;
}
```

* 绑定环回设备

`cma_bind_loopback`绑定环回设备，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_bind_loopback(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev, *cur_dev;
	union ib_gid gid;
	enum ib_port_state port_state;
	unsigned int p;
	u16 pkey;
	int ret;

	cma_dev = NULL;
	mutex_lock(&lock);
	// 遍历所有CMA设备
	list_for_each_entry(cur_dev, &dev_list, list) {
		// 过滤非IB设备或不支持CM的设备
		if (cma_family(id_priv) == AF_IB && !rdma_cap_ib_cm(cur_dev->device, 1))
			continue;

		if (!cma_dev) cma_dev = cur_dev;
		rdma_for_each_port (cur_dev->device, p) {
			// 过滤非活动端口
			if (!ib_get_cached_port_state(cur_dev->device, p, &port_state) &&
			    port_state == IB_PORT_ACTIVE) {
				cma_dev = cur_dev;
				goto port_found;
			}
		}
	}
	// 没有找到活动端口时，返回错误
	if (!cma_dev) {
		ret = -ENODEV;
		goto out;
	}

	p = 1;

port_found:
	// 查询GID
	ret = rdma_query_gid(cma_dev->device, p, 0, &gid);
	if (ret) goto out;
	// 查询PKEY
	ret = ib_get_cached_pkey(cma_dev->device, p, 0, &pkey);
	if (ret) goto out;

	// 设置设备类型为IB或以太网
	id_priv->id.route.addr.dev_addr.dev_type =
		(rdma_protocol_ib(cma_dev->device, p)) ? ARPHRD_INFINIBAND : ARPHRD_ETHER;
	// 设置源地址的SGID和PKEY
	rdma_addr_set_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	ib_addr_set_pkey(&id_priv->id.route.addr.dev_addr, pkey);
	id_priv->id.port_num = p;
	// 绑定到设备
	cma_attach_to_dev(id_priv, cma_dev);
	// 添加到资源跟踪列表
	rdma_restrack_add(&id_priv->res);
	// 设置环回地址
	cma_set_loopback(cma_src_addr(id_priv));
out:
	mutex_unlock(&lock);
	return ret;
}
```

* 通知解析完成

在解析本地环回地址完成后，通过wq队列通知用户空间解析完成。`enqueue_resolve_addr_work`添加work到wq队列，如下：

```c
// file: drivers/infiniband/core/cma.c
static void enqueue_resolve_addr_work(struct cma_work *work, struct rdma_id_private *id_priv)
{
	// 增加引用计数
	cma_id_get(id_priv);
	// 设置work的成员变量
	work->id = id_priv;
	// 初始化wq
	INIT_WORK(&work->work, cma_work_handler);
	// 设置work的状态
	work->old_state = RDMA_CM_ADDR_QUERY;
	work->new_state = RDMA_CM_ADDR_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ADDR_RESOLVED;
	queue_work(cma_wq, &work->work);
}
```

``work`设置的执行函数为`cma_work_handler`，如下：

```c
// file: drivers/infiniband/core/cma.c
static void cma_work_handler(struct work_struct *_work)
{
	struct cma_work *work = container_of(_work, struct cma_work, work);
	struct rdma_id_private *id_priv = work->id;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) == RDMA_CM_DESTROYING ||
	    READ_ONCE(id_priv->state) == RDMA_CM_DEVICE_REMOVAL)
		goto out_unlock;
	if (work->old_state != 0 || work->new_state != 0) {
		// 检查并更新状态
		if (!cma_comp_exch(id_priv, work->old_state, work->new_state))
			goto out_unlock;
	}
	// 处理事件
	if (cma_cm_event_handler(id_priv, &work->event)) {  ... }

out_unlock:
	mutex_unlock(&id_priv->handler_mutex);
	cma_id_put(id_priv);
out_free:
	if (work->event.event == RDMA_CM_EVENT_MULTICAST_JOIN)
		rdma_destroy_ah_attr(&work->event.param.ud.ah_attr);
	kfree(work);
}
```

##### 2. 解析IP地址

`rdma_resolve_ip`解析IP地址，如下：

```c
// file: drivers/infiniband/core/addr.c
int rdma_resolve_ip(struct sockaddr *src_addr, const struct sockaddr *dst_addr,
		    struct rdma_dev_addr *addr, unsigned long timeout_ms,
		    void (*callback)(int status, struct sockaddr *src_addr,
				     struct rdma_dev_addr *addr, void *context),
		    bool resolve_by_gid_attr, void *context)
{
	struct sockaddr *src_in, *dst_in;
	struct addr_req *req;
	int ret = 0;
	// 创建解析请求
	req = kzalloc_obj(*req);
	if (!req) return -ENOMEM;

	// 设置源地址和目的地址
	src_in = (struct sockaddr *) &req->src_addr;
	dst_in = (struct sockaddr *) &req->dst_addr;

	if (src_addr) {
		// 检查源地址和目的地址的协议族是否一致
		if (src_addr->sa_family != dst_addr->sa_family) { ... }
		memcpy(src_in, src_addr, rdma_addr_size(src_addr));
	} else {
		src_in->sa_family = dst_addr->sa_family;
	}
	memcpy(dst_in, dst_addr, rdma_addr_size(dst_addr));
	// 设置解析参数
	req->addr = addr;
	req->callback = callback;
	req->context = context;
	req->resolve_by_gid_attr = resolve_by_gid_attr;
	INIT_DELAYED_WORK(&req->work, process_one_req);
	req->seq = (u32)atomic_inc_return(&ib_nl_addr_request_seq);
	// 发起地址解析请求
	req->status = addr_resolve(src_in, dst_in, addr, true, req->resolve_by_gid_attr, req->seq);
	switch (req->status) {
	case 0:
		// 设置超时时间
		req->timeout = jiffies;
		queue_req(req);
		break;
	case -ENODATA:
		// 设置超时时间
		req->timeout = msecs_to_jiffies(timeout_ms) + jiffies;
		queue_req(req);
		break;
	default:
		ret = req->status;
		goto err;
	}
	return ret;
err:
	kfree(req);
	return ret;
}
```

* 解析IP地址

`addr_resolve`解析IP地址，如下：

```c
// file: drivers/infiniband/core/addr.c
static int addr_resolve(struct sockaddr *src_in, const struct sockaddr *dst_in,
			struct rdma_dev_addr *addr, bool resolve_neigh,
			bool resolve_by_gid_attr, u32 seq)
{
	struct dst_entry *dst = NULL;
	struct rtable *rt = NULL;
	int ret;

	if (!addr->net) {
		pr_warn_ratelimited("%s: missing namespace\n", __func__);
		return -EINVAL;
	}

	rcu_read_lock();
	if (resolve_by_gid_attr) {
		...
		// 从GID属性中获取网络命名空间
		ret = set_addr_netns_by_gid_rcu(addr);
		if (ret) { ... }
	}
	if (src_in->sa_family == AF_INET) {
		// 解析IPv4地址
		ret = addr4_resolve(src_in, dst_in, addr, &rt);
		dst = &rt->dst;
	} else {
		// 解析IPv6地址
		ret = addr6_resolve(src_in, dst_in, addr, &dst);
	}
	if (ret) {
		rcu_read_unlock();
		goto done;
	}
	// 设置源地址
	ret = rdma_set_src_addr_rcu(addr, dst_in, dst);
	rcu_read_unlock();

	if (!ret && resolve_neigh)
		// 解析邻居地址
		ret = addr_resolve_neigh(dst, dst_in, addr, seq);
	if (src_in->sa_family == AF_INET)
		ip_rt_put(rt);
	else
		dst_release(dst);
done:
	if (resolve_by_gid_attr)
		rdma_addr_set_net_defaults(addr);
	return ret;
}
```

* 提交解析请求

`queue_req`提交解析请求，如下：

```c
// file: drivers/infiniband/core/addr.c
static void queue_req(struct addr_req *req)
{
	spin_lock_bh(&lock);
	list_add_tail(&req->list, &req_list);
	set_timeout(req, req->timeout);
	spin_unlock_bh(&lock);
}
```

`req`设置的`wq`的执行函数为`process_one_req`，其实现如下：

```c
// file: drivers/infiniband/core/addr.c
static void process_one_req(struct work_struct *_work)
{
	struct addr_req *req;
	struct sockaddr *src_in, *dst_in;

	req = container_of(_work, struct addr_req, work.work);

	if (req->status == -ENODATA) {
		// 重新解析地址
		src_in = (struct sockaddr *)&req->src_addr;
		dst_in = (struct sockaddr *)&req->dst_addr;
		req->status = addr_resolve(src_in, dst_in, req->addr, true, 
						req->resolve_by_gid_attr, req->seq);
		if (req->status && time_after_eq(jiffies, req->timeout)) {
			// 解析超时
			req->status = -ETIMEDOUT;
		} else if (req->status == -ENODATA) {
			// 重新添加到解析请求队列
			spin_lock_bh(&lock);
			if (!list_empty(&req->list)) set_timeout(req, req->timeout);
			spin_unlock_bh(&lock);
			return;
		}
	}
	// 调用回调函数
	req->callback(req->status, (struct sockaddr *)&req->src_addr, req->addr, req->context);
	req->callback = NULL;

	spin_lock_bh(&lock);
	// 取消延迟工作
	cancel_delayed_work(&req->work);
	if (!list_empty(&req->list)) {
		list_del_init(&req->list);
		kfree(req);
	}
	spin_unlock_bh(&lock);
}
```

* 通知解析完成

`req->callback`是解析完成后的回调函数，设置为`addr_handler`, 用于通知解析完成。实现如下：

```c
// file: drivers/infiniband/core/cma.c
static void addr_handler(int status, struct sockaddr *src_addr, struct rdma_dev_addr *dev_addr, void *context)
{
	struct rdma_id_private *id_priv = context;
	struct rdma_cm_event event = {};
	struct sockaddr *addr;
	struct sockaddr_storage old_addr;

	mutex_lock(&id_priv->handler_mutex);
	// 检查是否是解析请求
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_RESOLVED))
		goto out;

	// 存储之前的源地址，以便在失败时恢复
	addr = cma_src_addr(id_priv);
	memcpy(&old_addr, addr, rdma_addr_size(addr));
	memcpy(addr, src_addr, rdma_addr_size(src_addr));
	if (!status && !id_priv->cma_dev) {
		// 尝试根据源IP地址获取rdma设备
		status = cma_acquire_dev_by_src_ip(id_priv);
		if (status)
			pr_debug_ratelimited("RDMA CM: ADDR_ERROR: failed to acquire device. status %d\n", status);
		rdma_restrack_add(&id_priv->res);
	} else if (status) {
		pr_debug_ratelimited("RDMA CM: ADDR_ERROR: failed to resolve IP. status %d\n", status);
	}

	if (status) {
		memcpy(addr, &old_addr, rdma_addr_size((struct sockaddr *)&old_addr));
		// 解析失败时，恢复之前的源地址
		if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_RESOLVED, RDMA_CM_ADDR_BOUND))
			goto out;
		// 通知解析失败事件
		event.event = RDMA_CM_EVENT_ADDR_ERROR;
		event.status = status;
	} else
		// 通知解析成功事件
		event.event = RDMA_CM_EVENT_ADDR_RESOLVED;
	// 通知事件处理函数
	if (cma_cm_event_handler(id_priv, &event)) {
		destroy_id_handler_unlock(id_priv);
		return;
	}
out:
	mutex_unlock(&id_priv->handler_mutex);
}
```

##### 3. 通知事件处理函数

解析本地地址或IP地址完成后，调用`cma_cm_event_handler`函数通知事件处理结果，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_cm_event_handler(struct rdma_id_private *id_priv, struct rdma_cm_event *event)
{
	int ret;

	lockdep_assert_held(&id_priv->handler_mutex);

	trace_cm_event_handler(id_priv, event);
	// 执行事件处理函数
	ret = id_priv->id.event_handler(&id_priv->id, event);
	trace_cm_event_done(id_priv, event, ret);
	return ret;
}
```

`event_handler`是CM事件处理函数，设置为`ucma_event_handler`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_create_id(struct ucma_file *file, const char __user *inbuf,
			      int in_len, int out_len)
{
	...
	cm_id = rdma_create_user_id(ucma_event_handler, ctx, cmd.ps, qp_type);
	...
}
```

`ucma_event_handler`将CM事件处理结果添加到用户空间的事件队列中。如下：

```c
// file: drivers/infiniband/core/ucma.c
static int ucma_event_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	struct ucma_event *uevent;
	struct ucma_context *ctx = cm_id->context;
	// 处理CONNECT_REQUEST事件
	if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
		return ucma_connect_event_handler(cm_id, event);

	if (ctx->uid) {
		// 创建用户事件
		uevent = ucma_create_uevent(ctx, event);
		if (!uevent) return 0;

		mutex_lock(&ctx->file->mut);
		// 添加到事件队列
		list_add_tail(&uevent->list, &ctx->file->event_list);
		mutex_unlock(&ctx->file->mut);
		wake_up_interruptible(&ctx->file->poll_wait);
	}
	// 处理设备移除事件
	if (event->event == RDMA_CM_EVENT_DEVICE_REMOVAL) {
		xa_lock(&ctx_table);
		if (xa_load(&ctx_table, ctx->id) == ctx)
			queue_work(system_dfl_wq, &ctx->close_work);
		xa_unlock(&ctx_table);
	}
	return 0;
}
```

#### 3.7.3 用户空间完成事件处理

用户空间在等待内核解析完成后，通过`ucma_complete`通知解析完成事件。实现如下：

```c
// file: rdma-core/librdmacm/cma.c
int ucma_complete(struct rdma_cm_id *id)
{
	struct cma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct cma_id_private, id);
	// 检查是否是同步解析请求
	if (!id_priv->sync) return 0;

	if (id_priv->id.event) {
		// 确认上一个事件处理
		rdma_ack_cm_event(id_priv->id.event);
		id_priv->id.event = NULL;
	}
	// 获取CM事件
	ret = rdma_get_cm_event(id_priv->id.channel, &id_priv->id.event);
	if (ret) return ret;

	if (id_priv->id.event->status) {
		// 处理解析失败事件
		if (id_priv->id.event->event == RDMA_CM_EVENT_REJECTED)
			ret = ERR(ECONNREFUSED);
		else if (id_priv->id.event->status < 0)
			ret = ERR(-id_priv->id.event->status);
		else
			ret = ERR(id_priv->id.event->status);
	}
	return ret;
}
```

在`rdma_get_cm_event`函数中，我们获取`RDMA_CM_EVENT_ADDR_RESOLVED`事件后，进行路由解析。我们暂时略过获取事件的过程，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_get_cm_event(struct rdma_event_channel *channel, struct rdma_cm_event **event)
{
	...
	switch (resp.event) {
	...
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ucma_process_addr_resolved(evt);
		break;
	...
	}
}
```

`ucma_process_addr_resolved`函数用于处理`RDMA_CM_EVENT_ADDR_RESOLVED`事件。在该事件发生后，我们需要查询路由信息。如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_process_addr_resolved(struct cma_event *evt)
{
	struct rdma_cm_id *id = &evt->id_priv->id;

	if (af_ib_support) {
		// 查询IB地址信息
		evt->event.status = ucma_query_addr(id);
		if (!evt->event.status && !id->verbs) goto err_dev;

		if (!evt->event.status && id->verbs->device->transport_type == IBV_TRANSPORT_IB) {
			// 查询IB GID信息
			evt->event.status = ucma_query_gid(id);
		}
	} else {
		// 查询IP路由信息
		evt->event.status = ucma_query_route(id);
		if (!evt->event.status && !id->verbs) goto err_dev;
	}
	// 处理路由解析错误事件
	if (evt->event.status)
		evt->event.event = RDMA_CM_EVENT_ADDR_ERROR;
	return;
err_dev:
	evt->event.status = ERR(ENODEV);
	evt->event.event = RDMA_CM_EVENT_ADDR_ERROR;
}
```

### 3.8 CM GET_EVENT

#### 3.8.1 用户空间GET_EVENT

在上一节中，我们通过`rdma_get_cm_event`函数获取CM事件。`rdma_get_cm_event`通过`GET_EVENT`命令和内核空间进行交互，在获取事件信息后进行初步的处理。如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_get_cm_event(struct rdma_event_channel *channel, struct rdma_cm_event **event)
{
	struct ucma_abi_event_resp resp = {};
	struct ucma_abi_get_event cmd;
	struct cma_event *evt;
	int ret;

	ret = ucma_init();
	if (ret) return ret;
	if (!event) return ERR(EINVAL);

	// 分配内存
	evt = malloc(sizeof(*evt));
	if (!evt) return ERR(ENOMEM);

retry:
	memset(evt, 0, sizeof(*evt));
	// 初始化`GET_EVENT`指令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, GET_EVENT, &resp, sizeof resp);
	ret = write(channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) { ... }

	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// 设置应答
	evt->event.event = resp.event;
	if (resp.uid) {
		// 通过`uid`获取`id_priv`, 
		evt->id_priv = (void *) (uintptr_t) resp.uid;
	} else {
		// 通过`id`获取`id_priv`, 只有在建立连接时使用
		evt->id_priv = ucma_lookup_id(resp.id);
		if (!evt->id_priv) { goto retry; }
		if (resp.event != RDMA_CM_EVENT_ESTABLISHED) {
			ucma_complete_event(evt->id_priv);
			goto retry;
		}
	}
	// 设置事件的`id`和状态
	evt->event.id = &evt->id_priv->id;
	evt->event.status = resp.status;

	// 初步处理事件
	switch (resp.event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ucma_process_addr_resolved(evt);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ucma_process_route_resolved(evt);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		...
		break;
	default:
		evt->id_priv = (void *) (uintptr_t) resp.uid;
		evt->event.id = &evt->id_priv->id;
		evt->event.status = resp.status;
		if (ucma_is_ud_qp(evt->id_priv->id.qp_type))
			ucma_copy_ud_event(evt, &resp.param.ud);
		else
			ucma_copy_conn_event(evt, &resp.param.conn);
		break;
	}
	// 返回`rdma_cm_event`
	*event = &evt->event;
	return 0;
}
```

目前CM事件定义如下：

```c
// file: include/rdma/rdma_cm.h
enum rdma_cm_event_type {
	RDMA_CM_EVENT_ADDR_RESOLVED,
	RDMA_CM_EVENT_ADDR_ERROR,
	RDMA_CM_EVENT_ROUTE_RESOLVED,
	RDMA_CM_EVENT_ROUTE_ERROR,
	RDMA_CM_EVENT_CONNECT_REQUEST,
	RDMA_CM_EVENT_CONNECT_RESPONSE,
	RDMA_CM_EVENT_CONNECT_ERROR,
	RDMA_CM_EVENT_UNREACHABLE,
	RDMA_CM_EVENT_REJECTED,
	RDMA_CM_EVENT_ESTABLISHED,
	RDMA_CM_EVENT_DISCONNECTED,
	RDMA_CM_EVENT_DEVICE_REMOVAL,
	RDMA_CM_EVENT_MULTICAST_JOIN,
	RDMA_CM_EVENT_MULTICAST_ERROR,
	RDMA_CM_EVENT_ADDR_CHANGE,
	RDMA_CM_EVENT_TIMEWAIT_EXIT,
	RDMA_CM_EVENT_ADDRINFO_RESOLVED,
	RDMA_CM_EVENT_ADDRINFO_ERROR,
	RDMA_CM_EVENT_USER,
	RDMA_CM_EVENT_INTERNAL,
};
```

我们将在后续详细分析每种事件的操作。

#### 3.8.2 内核空间处理GET_EVENT

`GET_EVENT`对应的处理函数为`ucma_get_event`。如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_get_event(struct ucma_file *file, const char __user *inbuf, int in_len, int out_len)
{
	struct rdma_ucm_get_event cmd;
	struct ucma_event *uevent;

	// 检查应答长度
	if (out_len < sizeof(uevent->resp) - sizeof(uevent->resp.reserved) - sizeof(uevent->resp.ece))
		return -ENOSPC;
	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) return -EFAULT;

	mutex_lock(&file->mut);
	// 事件为空时等待
	while (list_empty(&file->event_list)) {
		mutex_unlock(&file->mut);
		if (file->filp->f_flags & O_NONBLOCK) return -EAGAIN;

		if (wait_event_interruptible(file->poll_wait, !list_empty(&file->event_list)))
			return -ERESTARTSYS;
		mutex_lock(&file->mut);
	}
	// 从事件列表中获取第一个事件，并复制到用户空间
	uevent = list_first_entry(&file->event_list, struct ucma_event, list);
	if (copy_to_user(u64_to_user_ptr(cmd.response), &uevent->resp,
			 min_t(size_t, out_len, sizeof(uevent->resp)))) {
		mutex_unlock(&file->mut);
		return -EFAULT;
	}
	// 删除`uevent`
	list_del(&uevent->list);
	uevent->ctx->events_reported++;
	if (uevent->mc) uevent->mc->events_reported++;
	if (uevent->resp.event == RDMA_CM_EVENT_CONNECT_REQUEST)
		atomic_inc(&uevent->ctx->backlog);
	mutex_unlock(&file->mut);

	kfree(uevent);
	return 0;
}
```

### 3.9 CM QUERY_ROUTE

在用户空间成功绑定端口后或者路由解析完成后，我们可以通过`ucma_query_route`获取cm id的路由信息，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	...
	CMA_INIT_CMD(&cmd, sizeof cmd, BIND_IP);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;
	memcpy(&cmd.addr, addr, addrlen);

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;
	// 查询路由信息
	return ucma_query_route(id);
}
```

#### 3.9.1 用户空间QUERY_ROUTE

`ucma_query_route`通过`QUERY_ROUTE`命令查询路由信息，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_query_route(struct rdma_cm_id *id)
{
	struct ucma_abi_query_route_resp resp;
	struct ucma_abi_query cmd;
	struct cma_id_private *id_priv;
	int ret, i;

	// 初始化`QUERY_ROUTE`命令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, QUERY_ROUTE, &resp, sizeof resp);
	id_priv = container_of(id, struct cma_id_private, id);
	// 设置cm id和路由索引
	cmd.id = id_priv->handle;
	resp.ibdev_index = UCMA_INVALID_IB_INDEX;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) return (ret >= 0) ? ERR(ENODATA) : -1;

	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	// 处理路由信息
	if (resp.num_paths) {
		id->route.path_rec = malloc(sizeof(*id->route.path_rec) * resp.num_paths);
		if (!id->route.path_rec) return ERR(ENOMEM);
		id->route.num_paths = resp.num_paths;
		for (i = 0; i < resp.num_paths; i++)
			ibv_copy_path_rec_from_kern(&id->route.path_rec[i], &resp.ib_route[i]);
	}
	// 复制路由信息
	memcpy(id->route.addr.addr.ibaddr.sgid.raw, resp.ib_route[0].sgid,
	       sizeof id->route.addr.addr.ibaddr.sgid);
	memcpy(id->route.addr.addr.ibaddr.dgid.raw, resp.ib_route[0].dgid,
	       sizeof id->route.addr.addr.ibaddr.dgid);
	// 复制PKEY
	id->route.addr.addr.ibaddr.pkey = resp.ib_route[0].pkey;
	// 复制源地址和目的地址
	memcpy(&id->route.addr.src_addr, &resp.src_addr, sizeof resp.src_addr);
	memcpy(&id->route.addr.dst_addr, &resp.dst_addr, sizeof resp.dst_addr);

	// cm id未绑定设备，且有节点GUID时获取设备
	if (!id_priv->cma_dev && resp.node_guid) {
		// 获取设备
		ret = ucma_get_device(id_priv, resp.node_guid, resp.ibdev_index);
		if (ret) return ret;
		// 设置端口号
		id_priv->id.port_num = resp.port_num;
	}
	return 0;
}
```

#### 3.9.2 内核空间处理QUERY_ROUTE

`QUERY_ROUTE`命令用于查询cm id的路由信息，对应的处理函数为`ucma_query_route`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_query_route(struct ucma_file *file, const char __user *inbuf, int in_len, int out_len)
{
	struct rdma_ucm_query cmd;
	struct rdma_ucm_query_route_resp resp;
	struct ucma_context *ctx;
	struct sockaddr *addr;
	int ret = 0;

	if (out_len < offsetof(struct rdma_ucm_query_route_resp, ibdev_index))
		return -ENOSPC;
	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) return -EFAULT;

	// 获取上下文
	ctx = ucma_get_ctx(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	mutex_lock(&ctx->mutex);
	memset(&resp, 0, sizeof resp);
	// 复制源地址和目的地址
	addr = (struct sockaddr *) &ctx->cm_id->route.addr.src_addr;
	memcpy(&resp.src_addr, addr, addr->sa_family == AF_INET ?
				     sizeof(struct sockaddr_in) :
				     sizeof(struct sockaddr_in6));
	addr = (struct sockaddr *) &ctx->cm_id->route.addr.dst_addr;
	memcpy(&resp.dst_addr, addr, addr->sa_family == AF_INET ?
				     sizeof(struct sockaddr_in) :
				     sizeof(struct sockaddr_in6));
	if (!ctx->cm_id->device)
		goto out;
	
	// 复制节点GUID和IB设备索引
	resp.node_guid = (__force __u64) ctx->cm_id->device->node_guid;
	resp.ibdev_index = ctx->cm_id->device->index;
	resp.port_num = ctx->cm_id->port_num;

	if (rdma_cap_ib_sa(ctx->cm_id->device, ctx->cm_id->port_num))
		// 复制IB路由信息
		ucma_copy_ib_route(&resp, &ctx->cm_id->route);
	else if (rdma_protocol_roce(ctx->cm_id->device, ctx->cm_id->port_num))
		// 复制ROCE路由信息
		ucma_copy_iboe_route(&resp, &ctx->cm_id->route);
	else if (rdma_protocol_iwarp(ctx->cm_id->device, ctx->cm_id->port_num))
		// 复制iWARP路由信息
		ucma_copy_iw_route(&resp, &ctx->cm_id->route);
out:
	mutex_unlock(&ctx->mutex);
	// 复制路由信息到用户空间
	if (copy_to_user(u64_to_user_ptr(cmd.response), &resp, min_t(size_t, out_len, sizeof(resp))))
		ret = -EFAULT;
	ucma_put_ctx(ctx);
	return ret;
}
```

#### 3.9.3 用户空间获取RDMA设备

在获取路由信息后，cm id未绑定设备，且有节点GUID时，需要根据节点GUID和IB设备索引获取设备。`ucma_get_device`实现改功能，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_get_device(struct cma_id_private *id_priv, __be64 guid, uint32_t idx)
{
	struct cma_device *cma_dev;
	int ret;

	pthread_mutex_lock(&mut);
	// 根据节点GUID或者设备索引获取设备
	cma_dev = ucma_get_cma_device(guid, idx);
	if (!cma_dev) {
		pthread_mutex_unlock(&mut);
		return ERR(ENODEV);
	}
	// 初始化设备
	ret = ucma_init_device(cma_dev);
	if (ret) goto out;

	if (!cma_dev->pd)
		// 分配PD
		cma_dev->pd = ibv_alloc_pd(cma_dev->verbs);
	if (!cma_dev->pd) { ... }
	// 设置verbs和PD
	id_priv->cma_dev = cma_dev;
	id_priv->id.verbs = cma_dev->verbs;
	id_priv->id.pd = cma_dev->pd;
out:
	if (ret) cma_dev->refcnt--;
	pthread_mutex_unlock(&mut);
	return ret;
}
```

`ucma_init_device`初始化设备，打开设备上下文后获取端口信息，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_init_device(struct cma_device *cma_dev)
{
	struct ibv_port_attr port_attr;
	struct ibv_device_attr attr;
	int i, ret;
	// 如果verbs已初始化，直接返回
	if (cma_dev->verbs) return 0;

	// 打开设备上下文
	cma_dev->verbs = ibv_open_device(cma_dev->dev);
	if (!cma_dev->verbs) return ERR(ENODEV);

	// 查询设备属性
	ret = ibv_query_device(cma_dev->verbs, &attr);
	if (ret) { ... }

	// 分配端口数组
	cma_dev->port = malloc(sizeof(*cma_dev->port) * attr.phys_port_cnt);
	if (!cma_dev->port) { ... }

	// 查询端口属性
	for (i = 1; i <= attr.phys_port_cnt; i++) {
		if (ibv_query_port(cma_dev->verbs, i, &port_attr))
			cma_dev->port[i - 1].link_layer = IBV_LINK_LAYER_UNSPECIFIED;
		else
			cma_dev->port[i - 1].link_layer = port_attr.link_layer;
	}
	// 设置端口数量, QP大小等限制
	cma_dev->port_cnt = attr.phys_port_cnt;
	cma_dev->max_qpsize = attr.max_qp_wr;
	cma_dev->max_initiator_depth = (uint8_t) attr.max_qp_init_rd_atom;
	cma_dev->max_responder_resources = (uint8_t) attr.max_qp_rd_atom;
	return 0;
err:
	ibv_close_device(cma_dev->verbs);
	cma_dev->verbs = NULL;
	return ret;
}
```

### 3.10 CM RESOLVE_ROUTE

在解析地址后，我们可以通过`rdma_resolve_route`函数解析路由，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_ep(struct rdma_cm_id **id, struct rdma_addrinfo *res,
		   struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr)
{
	struct rdma_cm_id *cm_id;
	struct cma_id_private *id_priv;
	int ret;
	...

	if (res->ai_route_len) {
		ret = rdma_set_option(cm_id, RDMA_OPTION_IB, RDMA_OPTION_IB_PATH,
				      res->ai_route, res->ai_route_len);
		if (!ret) ret = ucma_complete(cm_id);
	} else {
		ret = rdma_resolve_route(cm_id, 2000);
	}
	if (ret) goto err;
	...
}
```

#### 3.10.1 用户空间RESOLVE_ROUTE

`rdma_resolve_route`通过`RESOLVE_ROUTE`命令解析路由信息，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms)
{
	struct ucma_abi_resolve_route cmd;
	struct cma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct cma_id_private, id);
	if (id->verbs->device->transport_type == IBV_TRANSPORT_IB) {
		// 设置IB路由信息
		ret = ucma_set_ib_route(id);
		if (!ret) goto out;
	}
	// 生成RESOLVE_ROUTE命令
	CMA_INIT_CMD(&cmd, sizeof cmd, RESOLVE_ROUTE);
	cmd.id = id_priv->handle;
	cmd.timeout_ms = timeout_ms;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) return (ret >= 0) ? ERR(ENODATA) : -1;

out:
	// 完成路由解析
	return ucma_complete(id);
}
```

#### 3.10.2 内核空间处理RESOLVE_ROUTE

`RESOLVE_ROUTE`对应的处理函数为`ucma_resolve_route`。如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_resolve_route(struct ucma_file *file, const char __user *inbuf,
				  int in_len, int out_len)
{
	struct rdma_ucm_resolve_route cmd;
	struct ucma_context *ctx;
	int ret;
	// 从用户空间复制命令
	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) return -EFAULT;
	// 获取上下文
	ctx = ucma_get_ctx_dev(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	mutex_lock(&ctx->mutex);
	// 解析路由
	ret = rdma_resolve_route(ctx->cm_id, cmd.timeout_ms);
	mutex_unlock(&ctx->mutex);
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_resolve_route`根据设备类型解析路由，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_resolve_route(struct rdma_cm_id *id, unsigned long timeout_ms)
{
	struct rdma_id_private *id_priv;
	enum rdma_cm_state state;
	int ret;

	if (!timeout_ms) return -EINVAL;

	id_priv = container_of(id, struct rdma_id_private, id);
	state = id_priv->state;
	// 检查是否已解析地址
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_RESOLVED, RDMA_CM_ROUTE_QUERY) &&
	    !cma_comp_exch(id_priv, RDMA_CM_ADDRINFO_RESOLVED, RDMA_CM_ROUTE_QUERY))
		return -EINVAL;

	cma_id_get(id_priv);
	if (rdma_cap_ib_sa(id->device, id->port_num))
		// 解析IB路由
		ret = cma_resolve_ib_route(id_priv, timeout_ms);
	else if (rdma_protocol_roce(id->device, id->port_num)) {
		// 解析ROCE路由
		ret = cma_resolve_iboe_route(id_priv);
		if (!ret) cma_add_id_to_tree(id_priv);
	}
	else if (rdma_protocol_iwarp(id->device, id->port_num))
		// 解析iwarp路由
		ret = cma_resolve_iw_route(id_priv);
	else
		ret = -ENOSYS;

	if (ret) goto err;
	return 0;
err:
	cma_comp_exch(id_priv, RDMA_CM_ROUTE_QUERY, state);
	cma_id_put(id_priv);
	return ret;
}
```

##### 1. ROCE路由解析

在设备支持`ROCE`协议时，`cma_resolve_iboe_route`实现ROCE路由解析，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_resolve_iboe_route(struct rdma_id_private *id_priv)
{
	struct rdma_route *route = &id_priv->id.route;
	struct rdma_addr *addr = &route->addr;
	struct cma_work *work;
	int ret;
	struct net_device *ndev;
	// 获取默认TOS
	u8 default_roce_tos = id_priv->cma_dev->default_roce_tos[id_priv->id.port_num -
					rdma_start_port(id_priv->cma_dev->device)];
	u8 tos;

	mutex_lock(&id_priv->qp_mutex);
	// 设置TOS
	tos = id_priv->tos_set ? id_priv->tos : default_roce_tos;
	mutex_unlock(&id_priv->qp_mutex);

	work = kzalloc_obj(*work);
	if (!work) return -ENOMEM;
	route->path_rec = kzalloc_obj(*route->path_rec);
	if (!route->path_rec) { ... }

	route->num_pri_alt_paths = 1;
	// 设置L2字段
	ndev = cma_iboe_set_path_rec_l2_fields(id_priv);
	if (!ndev) { ... }

	// 将源/目的的IP地址转换为GID
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.src_addr, &route->path_rec->sgid);
	rdma_ip2gid((struct sockaddr *)&id_priv->id.route.addr.dst_addr, &route->path_rec->dgid);

	// 设置hoplimit
	if (((struct sockaddr *)&id_priv->id.route.addr.dst_addr)->sa_family != AF_IB)
		route->path_rec->hop_limit = addr->dev_addr.hoplimit;
	else
		route->path_rec->hop_limit = 1;
	// 设置路由相关字段
	route->path_rec->reversible = 1;
	route->path_rec->pkey = cpu_to_be16(0xffff);
	route->path_rec->mtu_selector = IB_SA_EQ;
	route->path_rec->sl = iboe_tos_to_sl(ndev, tos);
	route->path_rec->traffic_class = tos;
	route->path_rec->mtu = iboe_get_mtu(ndev->mtu);
	route->path_rec->rate_selector = IB_SA_EQ;
	route->path_rec->rate = IB_RATE_PORT_CURRENT;
	dev_put(ndev);
	route->path_rec->packet_life_time_selector = IB_SA_EQ;
	mutex_lock(&id_priv->qp_mutex);
	if (id_priv->timeout_set && id_priv->timeout)
		route->path_rec->packet_life_time = id_priv->timeout - 1;
	else
		route->path_rec->packet_life_time = CMA_IBOE_PACKET_LIFETIME;
	mutex_unlock(&id_priv->qp_mutex);

	if (!route->path_rec->mtu) { ... }
	// 设置FlowLabel
	if (rdma_protocol_roce_udp_encap(id_priv->id.device, id_priv->id.port_num))
		route->path_rec->flow_label = cma_get_roce_udp_flow_label(id_priv);

	// 初始化解析路由工作
	cma_init_resolve_route_work(work, id_priv);
	queue_work(cma_wq, &work->work);
	return 0;
err2:
	kfree(route->path_rec);
	route->path_rec = NULL;
	route->num_pri_alt_paths = 0;
err1:
	kfree(work);
	return ret;
}
```

`cma_init_resolve_route_work`设置解析状态，如下：

```c
// file: drivers/infiniband/core/cma.c
static void cma_init_resolve_route_work(struct cma_work *work, struct rdma_id_private *id_priv)
{
	work->id = id_priv;
	// 初始化工作队列
	INIT_WORK(&work->work, cma_work_handler);
	work->old_state = RDMA_CM_ROUTE_QUERY;
	work->new_state = RDMA_CM_ROUTE_RESOLVED;
	// 设置路由解析事件
	work->event.event = RDMA_CM_EVENT_ROUTE_RESOLVED;
}
```

##### 2. iwarp路由解析

`cma_resolve_iw_route`函数解析iwarp路由，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_resolve_iw_route(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	work = kzalloc_obj(*work);
	if (!work) return -ENOMEM;
	// 初始化解析路由工作
	cma_init_resolve_route_work(work, id_priv);
	queue_work(cma_wq, &work->work);
	return 0;
}
```

#### 3.10.3 用户空间完成事件处理

用户空间在等待内核解析完成后，通过`ucma_complete`通知解析完成事件。在`rdma_get_cm_event`函数中，我们获取`RDMA_CM_EVENT_ROUTE_RESOLVED`事件后，进行路由解析。我们暂时略过获取事件的过程，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_get_cm_event(struct rdma_event_channel *channel, struct rdma_cm_event **event)
{
	...
	switch (resp.event) {
	...
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ucma_process_route_resolved(evt);
		break;
	...
	}
}
```

`ucma_process_route_resolved`函数用于处理`RDMA_CM_EVENT_ROUTE_RESOLVED`事件。在该事件发生后，我们需要查询路由信息。如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_process_route_resolved(struct cma_event *evt)
{
	if (evt->id_priv->id.verbs->device->transport_type != IBV_TRANSPORT_IB)
		return;

	if (af_ib_support)
		// 查询IB路径信息
		evt->event.status = ucma_query_path(&evt->id_priv->id);
	else
		// 查询IP路由信息
		evt->event.status = ucma_query_route(&evt->id_priv->id);

	if (evt->event.status)
		evt->event.event = RDMA_CM_EVENT_ROUTE_ERROR;
}
```

### 3.11 创建QP

接下来，我们通过`rdma_create_qp`创建QP，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_qp(struct rdma_cm_id *id, struct ibv_pd *pd,
		   struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_qp_init_attr_ex attr_ex;
	int ret;
	// 设置扩展属性
	memcpy(&attr_ex, qp_init_attr, sizeof(*qp_init_attr));
	// 设置PD
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = pd ? pd : id->pd;
	ret = rdma_create_qp_ex(id, &attr_ex);
	memcpy(qp_init_attr, &attr_ex, sizeof(*qp_init_attr));
	return ret;
}
```

`rdma_create_qp_ex`完成qp的创建，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_create_qp_ex(struct rdma_cm_id *id, struct ibv_qp_init_attr_ex *attr)
{
	struct cma_id_private *id_priv;
	struct ibv_qp *qp;
	int ret;

	// 检查QP是否已存在
	if (id->qp) return ERR(EINVAL);

	id_priv = container_of(id, struct cma_id_private, id);
	// 检查PD是否有效
	if (!(attr->comp_mask & IBV_QP_INIT_ATTR_PD) || !attr->pd) {
		attr->comp_mask |= IBV_QP_INIT_ATTR_PD;
		attr->pd = id->pd;
	} else if (id->verbs != attr->pd->context)
		return ERR(EINVAL);

	if ((id->recv_cq && attr->recv_cq && id->recv_cq != attr->recv_cq) ||
	    (id->send_cq && attr->send_cq && id->send_cq != attr->send_cq))
		return ERR(EINVAL);

	// 检查XRC是否有效
	if (id->qp_type == IBV_QPT_XRC_RECV) {
		if (!(attr->comp_mask & IBV_QP_INIT_ATTR_XRCD) || !attr->xrcd) {
			attr->xrcd = ucma_get_xrcd(id_priv->cma_dev);
			if (!attr->xrcd) return -1;
			attr->comp_mask |= IBV_QP_INIT_ATTR_XRCD;
		}
	}

	// 创建CQ
	ret = ucma_create_cqs(id, attr->send_cq || id->send_cq ? 0 : attr->cap.max_send_wr,
				  attr->recv_cq || id->recv_cq ? 0 : attr->cap.max_recv_wr);
	if (ret) return ret;

	// 设置CQ
	if (!attr->send_cq) attr->send_cq = id->send_cq;
	if (!attr->recv_cq) attr->recv_cq = id->recv_cq;
	if (id->srq && !attr->srq) attr->srq = id->srq;
	// 创建QP
	qp = ibv_create_qp_ex(id->verbs, attr);
	if (!qp) { ... }

	// 初始化ECE
	ret = init_ece(id, qp);
	if (ret) goto err2;

	if (ucma_is_ud_qp(id->qp_type))
		// 初始化UD QP
		ret = ucma_init_ud_qp(id_priv, qp);
	else
		// 初始化连接QP
		ret = ucma_init_conn_qp(id_priv, qp);
	if (ret) goto err2;
	// 设置本地ECE
	ret = set_local_ece(id, qp);
	if (ret) goto err2;
	// 设置PD和QP
	id->pd = qp->pd;
	id->qp = qp;
	return 0;
err2:
	ibv_destroy_qp(qp);
err1:
	ucma_destroy_cqs(id);
	return ret;
}
```

#### 3.11.1 创建CQ

`ucma_create_cqs`函数创建CQ，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_create_cqs(struct rdma_cm_id *id, uint32_t send_size, uint32_t recv_size)
{
	if (recv_size) {
		// 创建接收CQ通道
		id->recv_cq_channel = ibv_create_comp_channel(id->verbs);
		if (!id->recv_cq_channel) goto err;
		// 创建接收CQ
		id->recv_cq = ibv_create_cq(id->verbs, recv_size, id, id->recv_cq_channel, 0);
		if (!id->recv_cq) goto err;
	}

	if (send_size) {
		// 创建发送CQ通道
		id->send_cq_channel = ibv_create_comp_channel(id->verbs);
		if (!id->send_cq_channel) goto err;
		// 创建发送CQ
		id->send_cq = ibv_create_cq(id->verbs, send_size, id, id->send_cq_channel, 0);
		if (!id->send_cq) goto err;
	}
	return 0;
err:
	ucma_destroy_cqs(id);
	return -1;
}
```

可以看到，发送CQ和接收CQ的创建过程是相似的，都是先创建通道，再创建CQ。

#### 3.11.2 创建QP

通过`ibv_create_qp_ex`创建QP，如下：

```c
// file: rdma-core/libibverbs/verbs.h
static inline struct ibv_qp *
ibv_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *qp_init_attr_ex)
{
	struct verbs_context *vctx;
	uint32_t mask = qp_init_attr_ex->comp_mask;

	if (mask == IBV_QP_INIT_ATTR_PD)
		// 创建QP
		return ibv_create_qp(qp_init_attr_ex->pd, (struct ibv_qp_init_attr *)qp_init_attr_ex);

	vctx = verbs_get_ctx_op(context, create_qp_ex);
	if (!vctx) { ... }
	// 通过`.create_qp_ex`接口创建QP
	return vctx->create_qp_ex(context, qp_init_attr_ex);
}
```

#### 3.11.3 初始化QP

##### 1. UD QP的初始化

`ucma_init_ud_qp`初始化UD QP，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_init_ud_qp(struct cma_id_private *id_priv, struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, ret;

	if (abi_ver == 3)
		// abi版本为3时，直接调用`ucma_init_ud_qp3`
		return ucma_init_ud_qp3(id_priv, qp);

	// 设置QP状态为INIT
	qp_attr.qp_state = IBV_QPS_INIT;
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	
	if (ret) return ret;
	// 修改QP状态为INIT
	ret = ibv_modify_qp(qp, &qp_attr, qp_attr_mask);
	if (ret) return ERR(ret);

	// 修改QP状态为RTR
	qp_attr.qp_state = IBV_QPS_RTR;
	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE);
	if (ret) return ERR(ret);

	// 修改QP状态为RTS
	qp_attr.qp_state = IBV_QPS_RTS;
	qp_attr.sq_psn = 0;
	ret = ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_SQ_PSN);
	return rdma_seterrno(ret);
}
```

`rdma_init_qp_attr`初始化QP属性，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_init_qp_attr(struct rdma_cm_id *id, struct ibv_qp_attr *qp_attr, int *qp_attr_mask)
{
	struct ucma_abi_init_qp_attr cmd;
	struct ib_uverbs_qp_attr resp;
	struct cma_id_private *id_priv;
	int ret;

	// 初始化`INIT_QP_ATTR`命令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, INIT_QP_ATTR, &resp, sizeof resp);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;
	cmd.qp_state = qp_attr->qp_state;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) return (ret >= 0) ? ERR(ENODATA) : -1;

	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);
	// 从内核空间复制QP属性
	ibv_copy_qp_attr_from_kern(qp_attr, &resp);
	*qp_attr_mask = resp.qp_attr_mask;
	return 0;
}
```

`ibv_copy_qp_attr_from_kern`从内核空间复制QP属性到用户空间，如下：

```c
// file: rdma-core/libibverbs/marshall.c
void ibv_copy_qp_attr_from_kern(struct ibv_qp_attr *dst, struct ib_uverbs_qp_attr *src)
{
	dst->cur_qp_state = src->cur_qp_state;
	dst->path_mtu = src->path_mtu;
	dst->path_mig_state = src->path_mig_state;
	dst->qkey = src->qkey;
	dst->rq_psn = src->rq_psn;
	dst->sq_psn = src->sq_psn;
	dst->dest_qp_num = src->dest_qp_num;
	dst->qp_access_flags = src->qp_access_flags;

	dst->cap.max_send_wr = src->max_send_wr;
	dst->cap.max_recv_wr = src->max_recv_wr;
	dst->cap.max_send_sge = src->max_send_sge;
	dst->cap.max_recv_sge = src->max_recv_sge;
	dst->cap.max_inline_data = src->max_inline_data;

	ibv_copy_ah_attr_from_kern(&dst->ah_attr, &src->ah_attr);
	ibv_copy_ah_attr_from_kern(&dst->alt_ah_attr, &src->alt_ah_attr);

	dst->pkey_index = src->pkey_index;
	dst->alt_pkey_index = src->alt_pkey_index;
	dst->en_sqd_async_notify = src->en_sqd_async_notify;
	dst->sq_draining = src->sq_draining;
	dst->max_rd_atomic = src->max_rd_atomic;
	dst->max_dest_rd_atomic = src->max_dest_rd_atomic;
	dst->min_rnr_timer = src->min_rnr_timer;
	dst->port_num = src->port_num;
	dst->timeout = src->timeout;
	dst->retry_cnt = src->retry_cnt;
	dst->rnr_retry = src->rnr_retry;
	dst->alt_port_num = src->alt_port_num;
	dst->alt_timeout = src->alt_timeout;
}
```

##### 2. 连接QP的初始化

`ucma_init_conn_qp`初始化连接QP，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_init_conn_qp(struct cma_id_private *id_priv, struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, ret;

	if (abi_ver == 3)
		// abi版本为3时，直接调用`ucma_init_conn_qp3`
		return ucma_init_conn_qp3(id_priv, qp);

	// 设置QP状态为INIT
	qp_attr.qp_state = IBV_QPS_INIT;
	// 初始化QP属性
	ret = rdma_init_qp_attr(&id_priv->id, &qp_attr, &qp_attr_mask);
	if (ret) return ret;
	// 设置QP状态为INIT
	return rdma_seterrno(ibv_modify_qp(qp, &qp_attr, qp_attr_mask));
}
```

### 3.12 CM LISTEN

服务端在创建CM端点后，我们可以通过CM LISTEN来监听端口，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 监听端口
	ret = rdma_listen(listen_id, 0);
	...
}
```

#### 3.12.1 用户空间LISTEN

`rdma_listen`通过`LISTEN`命令和内核空间进行交互，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_listen(struct rdma_cm_id *id, int backlog)
{
	struct ucma_abi_listen cmd;
	struct cma_id_private *id_priv;
	int ret;

	// 初始化`LISTEN`命令
	CMA_INIT_CMD(&cmd, sizeof cmd, LISTEN);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;
	cmd.backlog = backlog;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;

	if (af_ib_support)
		return ucma_query_addr(id);
	else
		return ucma_query_route(id);
}
```

#### 3.12.2 内核空间处理LISTEN

`LISTEN`命令用于监听cm id的端口，对应的处理函数为`ucma_listen`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_listen(struct ucma_file *file, const char __user *inbuf,
			   int in_len, int out_len)
{
	struct rdma_ucm_listen cmd;
	struct ucma_context *ctx;
	int ret;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;
	// 获取上下文
	ctx = ucma_get_ctx(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	// 检查backlog参数
	if (cmd.backlog <= 0 || cmd.backlog > max_backlog)
		cmd.backlog = max_backlog;
	atomic_set(&ctx->backlog, cmd.backlog);

	mutex_lock(&ctx->mutex);
	// 调用rdma_listen监听端口
	ret = rdma_listen(ctx->cm_id, cmd.backlog);
	mutex_unlock(&ctx->mutex);
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_listen`函数进行实际的监听操作，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_listen(struct rdma_cm_id *id, int backlog)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	int ret;
	// 没有bind时，进行bind
	if (!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_LISTEN)) {
		struct sockaddr_in any_in = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};
		// 绑定任意地址
		ret = rdma_bind_addr(id, (struct sockaddr *)&any_in);
		if (ret) return ret;
		// 设置为监听状态
		if (WARN_ON(!cma_comp_exch(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_LISTEN)))
			return -EINVAL;
	}
	// reuseaddr检查
	if (id_priv->reuseaddr) {
		mutex_lock(&lock);
		ret = cma_check_port(id_priv->bind_list, id_priv, 0);
		if (!ret) id_priv->reuseaddr = 0;
		mutex_unlock(&lock);
		if (ret) goto err;
	}

	id_priv->backlog = backlog;
	if (id_priv->cma_dev) {
		if (rdma_cap_ib_cm(id->device, 1)) {
			// IB/ROCE设备监听
			ret = cma_ib_listen(id_priv);
			if (ret) goto err;
		} else if (rdma_cap_iw_cm(id->device, 1)) {
			// iWARP监听
			ret = cma_iw_listen(id_priv, backlog);
			if (ret) goto err;
		} else {
			ret = -ENOSYS;
			goto err;
		}
	} else {
		// 未关联cma设备时，监听所有的设备
		ret = cma_listen_on_all(id_priv);
		if (ret) goto err;
	}
	return 0;
err:
	id_priv->backlog = 0;
	cma_comp_exch(id_priv, RDMA_CM_LISTEN, RDMA_CM_ADDR_BOUND);
	return ret;
}
```

在没有指定设备时，`cma_listen_on_all`监听所有的设备，如下:

```c
// file: drivers/infiniband/core/cma.c
static int cma_listen_on_all(struct rdma_id_private *id_priv)
{
	struct rdma_id_private *to_destroy;
	struct cma_device *cma_dev;
	int ret;

	mutex_lock(&lock);
	// 添加到`listen_any_list`
	list_add_tail(&id_priv->listen_any_item, &listen_any_list);
	// 遍历所有的设备
	list_for_each_entry(cma_dev, &dev_list, list) {
		// 在设备上进行监听
		ret = cma_listen_on_dev(id_priv, cma_dev, &to_destroy);
		if (ret) {
			if (to_destroy)list_del_init(&to_destroy->device_item);
			goto err_listen;
		}
	}
	mutex_unlock(&lock);
	return 0;
err_listen:
	_cma_cancel_listens(id_priv);
	mutex_unlock(&lock);
	if (to_destroy)rdma_destroy_id(&to_destroy->id);
	return ret;
}
```

`cma_listen_on_dev`在指定的设备上监听，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_listen_on_dev(struct rdma_id_private *id_priv, struct cma_device *cma_dev,
			     struct rdma_id_private **to_destroy)
{
	struct rdma_id_private *dev_id_priv;
	struct net *net = id_priv->id.route.addr.dev_addr.net;
	int ret;

	lockdep_assert_held(&lock);

	*to_destroy = NULL;
	// IB设备且不支持CM时，直接返回
	if (cma_family(id_priv) == AF_IB && !rdma_cap_ib_cm(cma_dev->device, 1))
		return 0;
	// 创建新的CM ID
	dev_id_priv = __rdma_create_id(net, cma_listen_handler, id_priv,
				 id_priv->id.ps, id_priv->id.qp_type, id_priv);
	if (IS_ERR(dev_id_priv)) return PTR_ERR(dev_id_priv);

	// 设置为绑定状态
	dev_id_priv->state = RDMA_CM_ADDR_BOUND;
	memcpy(cma_src_addr(dev_id_priv), cma_src_addr(id_priv),
	       rdma_addr_size(cma_src_addr(id_priv)));

	_cma_attach_to_dev(dev_id_priv, cma_dev);
	rdma_restrack_add(&dev_id_priv->res);
	cma_id_get(id_priv);
	dev_id_priv->internal_id = 1;
	dev_id_priv->afonly = id_priv->afonly;
	mutex_lock(&id_priv->qp_mutex);
	dev_id_priv->tos_set = id_priv->tos_set;
	dev_id_priv->tos = id_priv->tos;
	mutex_unlock(&id_priv->qp_mutex);
	// 进行监听
	ret = rdma_listen(&dev_id_priv->id, id_priv->backlog);
	if (ret) goto err_listen;
	list_add_tail(&dev_id_priv->listen_item, &id_priv->listen_list);
	return 0;
err_listen:
	*to_destroy = dev_id_priv;
	dev_warn(&cma_dev->device->dev, "RDMA CMA: %s, error %d\n", __func__, ret);
	return ret;
}
```

### 3.13 CM CONNECT

在分析服务端LISTEN之后，接下来我们分析客戶端CONNECT的过程，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_client.c
static int run(void)
{
	...
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 连接服务端
	ret = rdma_connect(id, NULL);
	...
}
```

#### 3.13.1 用户空间CONNECT

`rdma_connect`通过`CONNECT`命令和内核空间进行交互，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	uint32_t qp_num = conn_param ? conn_param->qp_num : 0;
	uint8_t srq = conn_param ? conn_param->srq : 0;
	struct ucma_abi_connect cmd;
	struct cma_id_private *id_priv;
	int ret;

	// 检查连接参数
	id_priv = container_of(id, struct cma_id_private, id);
	ret = ucma_valid_param(id_priv, conn_param);
	if (ret) return ret;

	// 获取`initiator_depth`和`responder_resources`参数
	if (conn_param && conn_param->initiator_depth != RDMA_MAX_INIT_DEPTH)
		id_priv->initiator_depth = conn_param->initiator_depth;
	else
		id_priv->initiator_depth = id_priv->cma_dev->max_initiator_depth;
	if (conn_param && conn_param->responder_resources != RDMA_MAX_RESP_RES)
		id_priv->responder_resources = conn_param->responder_resources;
	else
		id_priv->responder_resources = id_priv->cma_dev->max_responder_resources;

	// 生成`CONNECT`指令
	CMA_INIT_CMD(&cmd, sizeof cmd, CONNECT);
	cmd.id = id_priv->handle;
	if (id->qp) {
		// 存在`qp`时，设置`qp_num`
		qp_num = id->qp->qp_num;
		srq = !!id->qp->srq;
	}
	// 复制连接参数和ece参数到内核
	ucma_copy_conn_param_to_kern(id_priv, &cmd.conn_param, conn_param, qp_num, srq);
	ucma_copy_ece_param_to_kern_req(id_priv, &cmd.ece);

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;

	if (id_priv->connect_len) {
		free(id_priv->connect);
		id_priv->connect_len = 0;
	}
	return ucma_complete(id);
}
```

#### 3.13.2 内核空间处理CONNECT

`CONNECT`命令用于连接对端cm id的端口，对应的处理函数为`ucma_connect`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_connect(struct ucma_file *file, const char __user *inbuf,
			    int in_len, int out_len)
{
	struct rdma_conn_param conn_param;
	struct rdma_ucm_ece ece = {};
	struct rdma_ucm_connect cmd;
	struct ucma_context *ctx;
	size_t in_size;
	int ret;

	// 检查连接参数
	if (in_len < offsetofend(typeof(cmd), reserved)) return -EINVAL;
	in_size = min_t(size_t, in_len, sizeof(cmd));
	if (copy_from_user(&cmd, inbuf, in_size)) return -EFAULT;
	if (!cmd.conn_param.valid) return -EINVAL;

	// 获取上下文
	ctx = ucma_get_ctx_dev(file, cmd.id);
	if (IS_ERR(ctx))return PTR_ERR(ctx);

	ucma_copy_conn_param(ctx->cm_id, &conn_param, &cmd.conn_param);
	if (offsetofend(typeof(cmd), ece) <= in_size) {
		ece.vendor_id = cmd.ece.vendor_id;
		ece.attr_mod = cmd.ece.attr_mod;
	}

	mutex_lock(&ctx->mutex);
	// 执行连接
	ret = rdma_connect_ece(ctx->cm_id, &conn_param, &ece);
	mutex_unlock(&ctx->mutex);
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_connect_ece`经过多次封装后调用`rdma_connect_locked`，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_connect_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param, struct rdma_ucm_ece *ece)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	// 设置ece参数
	id_priv->ece.vendor_id = ece->vendor_id;
	id_priv->ece.attr_mod = ece->attr_mod;
	return rdma_connect(id, conn_param);
}
// file: drivers/infiniband/core/cma.c
int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	ret = rdma_connect_locked(id, conn_param);
	mutex_unlock(&id_priv->handler_mutex);
	return ret;
}
```

`rdma_connect_locked`进行实际的连接操作，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_connect_locked(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	int ret;

	lockdep_assert_held(&id_priv->handler_mutex);
	// 设置为连接状态
	if (!cma_comp_exch(id_priv, RDMA_CM_ROUTE_RESOLVED, RDMA_CM_CONNECT))
		return -EINVAL;

	if (!id->qp) {
		//  设置`qp_num`和`srq`
		id_priv->qp_num = conn_param->qp_num;
		id_priv->srq = conn_param->srq;
	}

	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		if (id->qp_type == IB_QPT_UD)
			// ud方式连接
			ret = cma_resolve_ib_udp(id_priv, conn_param);
		else
			// 其他方式连接
			ret = cma_connect_ib(id_priv, conn_param);
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		// iwarp连接
		ret = cma_connect_iw(id_priv, conn_param);
	} else {
		ret = -ENOSYS;
	}
	if (ret) goto err_state;
	return 0;
err_state:
	cma_comp_exch(id_priv, RDMA_CM_CONNECT, RDMA_CM_ROUTE_RESOLVED);
	return ret;
}
```

### 3.14 服务端获取连接请求

在服务端监听成功后，通过`rdma_get_request`获取连接请求，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 监听端口
	ret = rdma_listen(listen_id, 0);
	...
	// 获取连接请求
	ret = rdma_get_request(listen_id, &id);
	...
}
```

#### 3.14.1 用户空间获取连接请求

`rdma_get_request`通过获取CM事件来获取连接请求，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_get_request(struct rdma_cm_id *listen, struct rdma_cm_id **id)
{
	struct cma_id_private *id_priv;
	struct rdma_cm_event *event;
	int ret;

	id_priv = container_of(listen, struct cma_id_private, id);
	// 检查是否为同步模式
	if (!id_priv->sync) return ERR(EINVAL);

	if (listen->event) {
		rdma_ack_cm_event(listen->event);
		listen->event = NULL;
	}
	// 获取CM事件
	ret = rdma_get_cm_event(listen->channel, &event);
	if (ret) return ret;

	// 检查事件类型
	if (event->event == RDMA_CM_EVENT_REJECTED) {
		ret = ERR(ECONNREFUSED);
		goto err;
	}
	if (event->status) {
		ret = ERR(-event->status);
		goto err;
	}
	// 检查事件是否为连接请求
	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		ret = ERR(EINVAL);
		goto err;
	}

	if (id_priv->qp_init_attr) {
		struct ibv_qp_init_attr attr;
		attr = *id_priv->qp_init_attr;
		// 创建qp
		ret = rdma_create_qp(event->id, listen->pd, &attr);
		if (ret) goto err;
	}
	// 返回连接请求的id
	*id = event->id;
	(*id)->event = event;
	return 0;
err:
	listen->event = event;
	return ret;
}
```

#### 3.14.2 用户空间完成事件处理

在`rdma_get_cm_event`函数中，我们获取`RDMA_CM_EVENT_CONNECT_REQUEST`事件后，复制连接参数后处理。我们暂时略过获取事件的过程，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_get_cm_event(struct rdma_event_channel *channel,
		      struct rdma_cm_event **event)
{
	...
	switch (resp.event) {
	...
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		evt->id_priv = (void *) (uintptr_t) resp.uid;
		if (ucma_is_ud_qp(evt->id_priv->id.qp_type))
			ucma_copy_ud_event(evt, &resp.param.ud);
		else
			ucma_copy_conn_event(evt, &resp.param.conn);

		ret = ucma_process_conn_req(evt, resp.id, &resp.ece);
		if (ret) goto retry;
		break;
	...
	}
}
```

##### 1. 复制连接参数

根据qp类型，通过`ucma_copy_ud_event`或`ucma_copy_conn_event`复制连接参数。如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_copy_ud_event(struct cma_event *event, struct ucma_abi_ud_param *src)
{
	struct rdma_ud_param *dst = &event->event.param.ud;
	// 复制私有数据
	dst->private_data_len = src->private_data_len;
	if (src->private_data_len) {
		dst->private_data = &event->private_data;
		memcpy(&event->private_data, src->private_data, src->private_data_len);
	}
	// 复制ah属性
	ibv_copy_ah_attr_from_kern(&dst->ah_attr, &src->ah_attr);
	// 复制qp num和qkey
	dst->qp_num = src->qp_num;
	dst->qkey = src->qkey;
}
```

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_copy_conn_event(struct cma_event *event, struct ucma_abi_conn_param *src)
{
	struct rdma_conn_param *dst = &event->event.param.conn;

	// 复制私有数据
	dst->private_data_len = src->private_data_len;
	if (src->private_data_len) {
		dst->private_data = &event->private_data;
		memcpy(&event->private_data, src->private_data, src->private_data_len);
	}
	// 复制其他参数
	dst->responder_resources = src->responder_resources;
	dst->initiator_depth = src->initiator_depth;
	dst->flow_control = src->flow_control;
	dst->retry_count = src->retry_count;
	dst->rnr_retry_count = src->rnr_retry_count;
	dst->srq = src->srq;
	dst->qp_num = src->qp_num;
}
```

##### 2. 处理连接请求

`ucma_process_conn_req`函数处理连接请求，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_process_conn_req(struct cma_event *evt, uint32_t handle, struct ucma_abi_ece *ece)
{
	struct cma_id_private *id_priv;
	int ret;
	// 创建新的id
	id_priv = ucma_alloc_id(evt->id_priv->id.channel, evt->id_priv->id.context, 
				evt->id_priv->id.ps, evt->id_priv->id.qp_type);
	if (!id_priv) { ... }

	// 设置事件参数
	evt->event.listen_id = &evt->id_priv->id;
	evt->event.id = &id_priv->id;
	id_priv->handle = handle;
	ucma_insert_id(id_priv);
	id_priv->initiator_depth = evt->event.param.conn.initiator_depth;
	id_priv->responder_resources = evt->event.param.conn.responder_resources;
	id_priv->remote_ece.vendor_id = ece->vendor_id;
	id_priv->remote_ece.options = ece->attr_mod;

	if (evt->id_priv->sync) {
		// 迁移ID
		ret = rdma_migrate_id(&id_priv->id, NULL);
		if (ret) goto err2;
	}
	// 查询连接请求的信息
	ret = ucma_query_req_info(&id_priv->id);
	if (ret) goto err2;
	return 0;
err2:
	rdma_destroy_id(&id_priv->id);
err1:
	ucma_complete_event(evt->id_priv);
	return ret;
}
```

##### 3. 迁移ID

`rdma_migrate_id`迁移ID，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_migrate_id(struct rdma_cm_id *id, struct rdma_event_channel *channel)
{
	struct ucma_abi_migrate_resp resp;
	struct ucma_abi_migrate_id cmd;
	struct cma_id_private *id_priv;
	int ret, sync;

	id_priv = container_of(id, struct cma_id_private, id);
	// 检查迁移设置
	if (id_priv->sync && !channel) return ERR(EINVAL);

	if ((sync = (channel == NULL))) {
		// 创建事件通道
		channel = rdma_create_event_channel();
		if (!channel) return -1;
	}
	// 初始化`MIGRATE_ID`命令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, MIGRATE_ID, &resp, sizeof resp);
	// 设置ID和事件通道FD
	cmd.id = id_priv->handle;
	cmd.fd = id->channel->fd;

	ret = write(channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) {
		// 失败时销毁事件通道
		if (sync) rdma_destroy_event_channel(channel);
		return (ret >= 0) ? ERR(ENODATA) : -1;
	}
	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	if (id_priv->sync) {
		if (id->event) {
			rdma_ack_cm_event(id->event);
			id->event = NULL;
		}
		// 销毁之前关联的事件通道
		rdma_destroy_event_channel(id->channel);
	}
	pthread_mutex_lock(&id_priv->mut);
	// 更新同步状态和事件通道
	id_priv->sync = sync;
	id->channel = channel;
	while (id_priv->events_completed < resp.events_reported)
		pthread_cond_wait(&id_priv->cond, &id_priv->mut);
	pthread_mutex_unlock(&id_priv->mut);
	return 0;
}
```

### 3.15 CM ACCEPT

在服务段获取连接请求后，通过`rdma_accept`接受连接请求，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 监听端口
	ret = rdma_listen(listen_id, 0);
	...
	// 获取连接请求
	ret = rdma_get_request(listen_id, &id);
	...
	// 接受连接请求
	ret = rdma_accept(id, NULL);
}
```

#### 3.15.1 用户空间ACCEPT

`rdma_accept`通过`ACCEPT`命令和内核空间进行交互，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	uint32_t qp_num = id->qp ? id->qp->qp_num : conn_param->qp_num;
	uint8_t srq = id->qp ? !!id->qp->srq : conn_param->srq;
	struct ucma_abi_accept cmd;
	struct cma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct cma_id_private, id);
	ret = ucma_valid_param(id_priv, conn_param);
	if (ret) return ret;

	// 设置初始化深度
	if (!conn_param || conn_param->initiator_depth == RDMA_MAX_INIT_DEPTH) {
		id_priv->initiator_depth = min(id_priv->initiator_depth,
					       id_priv->cma_dev->max_initiator_depth);
	} else {
		id_priv->initiator_depth = conn_param->initiator_depth;
	}
	// 设置响应资源
	if (!conn_param || conn_param->responder_resources == RDMA_MAX_RESP_RES) {
		id_priv->responder_resources = min(id_priv->responder_resources,
						   id_priv->cma_dev->max_responder_resources);
	} else {
		id_priv->responder_resources = conn_param->responder_resources;
	}

	if (!ucma_is_ud_qp(id->qp_type)) {
		// 非UP QP设置RTR和RTS
		ret = ucma_modify_qp_rtr(id, id_priv->responder_resources);
		if (ret) return ret;
		ret = ucma_modify_qp_rts(id, id_priv->initiator_depth);
		if (ret) return ret;
	}

	// 初始化`ACCEPT`命令
	CMA_INIT_CMD(&cmd, sizeof cmd, ACCEPT);
	cmd.id = id_priv->handle;
	cmd.uid = (uintptr_t) id_priv;
	// 复制连接参数到内核空间
	ucma_copy_conn_param_to_kern(id_priv, &cmd.conn_param, conn_param, qp_num, srq);
	// 复制ECE参数到内核空间
	ucma_copy_ece_param_to_kern_rep(id_priv, &cmd.ece);

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd) {
		ucma_modify_qp_err(id);
		return (ret >= 0) ? ERR(ENODATA) : -1;
	}

	if (ucma_is_ud_qp(id->qp_type)) {
		if (id_priv->sync && id_priv->id.event) {
			rdma_ack_cm_event(id_priv->id.event);
			id_priv->id.event = NULL;
		}
		return 0;
	}
	// 完成ID
	return ucma_complete(id);
}
```

#### 3.15.2 内核空间处理ACCEPT

`ACCEPT`命令用于接受对端cm id的连接请求，对应的处理函数为`ucma_accept`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_accept(struct ucma_file *file, const char __user *inbuf,
			   int in_len, int out_len)
{
	struct rdma_ucm_accept cmd;
	struct rdma_conn_param conn_param;
	struct rdma_ucm_ece ece = {};
	struct ucma_context *ctx;
	size_t in_size;
	int ret;

	if (in_len < offsetofend(typeof(cmd), reserved))
		return -EINVAL;
	in_size = min_t(size_t, in_len, sizeof(cmd));
	if (copy_from_user(&cmd, inbuf, in_size))
		return -EFAULT;

	ctx = ucma_get_ctx_dev(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	// 复制ECE参数到内核空间
	if (offsetofend(typeof(cmd), ece) <= in_size) {
		ece.vendor_id = cmd.ece.vendor_id;
		ece.attr_mod = cmd.ece.attr_mod;
	}

	if (cmd.conn_param.valid) {
		// 复制连接参数到内核空间
		ucma_copy_conn_param(ctx->cm_id, &conn_param, &cmd.conn_param);
		mutex_lock(&ctx->mutex);
		rdma_lock_handler(ctx->cm_id);
		// 接受连接请求
		ret = rdma_accept_ece(ctx->cm_id, &conn_param, &ece);
		if (!ret) {
			ctx->uid = cmd.uid;
		}
		rdma_unlock_handler(ctx->cm_id);
		mutex_unlock(&ctx->mutex);
	} else {
		mutex_lock(&ctx->mutex);
		rdma_lock_handler(ctx->cm_id);
		// 接受连接请求
		ret = rdma_accept_ece(ctx->cm_id, NULL, &ece);
		rdma_unlock_handler(ctx->cm_id);
		mutex_unlock(&ctx->mutex);
	}
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_accept_ece`复制`ece`参数后，调用`rdma_accept`接受连接请求，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_accept_ece(struct rdma_cm_id *id, struct rdma_conn_param *conn_param, struct rdma_ucm_ece *ece)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	// 复制ECE参数
	id_priv->ece.vendor_id = ece->vendor_id;
	id_priv->ece.attr_mod = ece->attr_mod;
	// 接受连接请求
	return rdma_accept(id, conn_param);
}
```

`rdma_accept`接收连接请求，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv = container_of(id, struct rdma_id_private, id);
	int ret;

	lockdep_assert_held(&id_priv->handler_mutex);
	// 检查ID状态是否为CONNECT
	if (READ_ONCE(id_priv->state) != RDMA_CM_CONNECT)
		return -EINVAL;

	if (!id->qp && conn_param) {
		// 设置QP号和SRQ
		id_priv->qp_num = conn_param->qp_num;
		id_priv->srq = conn_param->srq;
	}
	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		if (id->qp_type == IB_QPT_UD) {
			// 发送SIDR回复
			if (conn_param)
				ret = cma_send_sidr_rep(id_priv, IB_SIDR_SUCCESS, conn_param->qkey,
							conn_param->private_data, conn_param->private_data_len);
			else
				ret = cma_send_sidr_rep(id_priv, IB_SIDR_SUCCESS, 0, NULL, 0);
		} else {
			if (conn_param)
				// 接受IB连接请求
				ret = cma_accept_ib(id_priv, conn_param);
			else
				// 回复连接请求
				ret = cma_rep_recv(id_priv);
		}
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		// iwarp接受连接请求
		ret = cma_accept_iw(id_priv, conn_param);
	} else {
		ret = -ENOSYS;
	}
	if (ret) goto reject;

	return 0;
reject:
	// 失败时，修改QP状态为ERROR
	cma_modify_qp_err(id_priv);
	// 拒绝连接请求
	rdma_reject(id, NULL, 0, IB_CM_REJ_CONSUMER_DEFINED);
	return ret;
}
```

### 3.16 CM收发数据

服务端和客户端都是通过`rdma_reg_msgs`,`rdma_post_recv`,`rdma_post_send`来收发数据，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
	// 注册接收消息的内存区域
	mr = rdma_reg_msgs(id, recv_msg, 16);
	if (!mr) { ... }
	if ((send_flags & IBV_SEND_INLINE) == 0) {
		// 注册发送消息的内存区域
		send_mr = rdma_reg_msgs(id, send_msg, 16);
		if (!send_mr) { ... }
	}
	// 提交接收请求
	ret = rdma_post_recv(id, NULL, recv_msg, 16, mr);
	if (ret) { ... }
	... 
	// 等待接收完成
	while ((ret = rdma_get_recv_comp(id, &wc)) == 0);
	if (ret < 0) { ... }

	// 提交发送请求
	ret = rdma_post_send(id, NULL, send_msg, 16, send_mr, send_flags);
	if (ret) { ... }
	// 等待发送完成
	while ((ret = rdma_get_send_comp(id, &wc)) == 0);
	...
}
```

#### 3.16.1 注册MR

`rdma_reg_msgs`注册消息内存区域，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline struct ibv_mr * rdma_reg_msgs(struct rdma_cm_id *id, void *addr, size_t length)
{
	// 注册消息内存区域
	return ibv_reg_mr(id->pd, addr, length, IBV_ACCESS_LOCAL_WRITE);
}
```

#### 3.16.2 提交接收请求

`rdma_post_recv`提交接收请求，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int
rdma_post_recv(struct rdma_cm_id *id, void *context, void *addr,
	       size_t length, struct ibv_mr *mr)
{
	struct ibv_sge sge;

	assert((addr >= mr->addr) &&
		(((uint8_t *) addr + length) <= ((uint8_t *) mr->addr + mr->length)));
	// 设置SGE
	sge.addr = (uint64_t) (uintptr_t) addr;
	sge.length = (uint32_t) length;
	sge.lkey = mr->lkey;
	// 提交接收请求
	return rdma_post_recvv(id, context, &sge, 1);
}
```

`rdma_post_recvv`提交接收请求到QP或SRQ，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int
rdma_post_recvv(struct rdma_cm_id *id, void *context, struct ibv_sge *sgl, int nsge)
{
	struct ibv_recv_wr wr, *bad;
	// 设置WR
	wr.wr_id = (uintptr_t) context;
	wr.next = NULL;
	wr.sg_list = sgl;
	wr.num_sge = nsge;

	if (id->srq)
		// 提交接收请求到SRQ
		return rdma_seterrno(ibv_post_srq_recv(id->srq, &wr, &bad));
	else
		// 提交接收请求到QP
		return rdma_seterrno(ibv_post_recv(id->qp, &wr, &bad));
}
```

#### 3.16.3 等待接收完成

`rdma_get_recv_comp`等待轮训完成队列，等待接收完成，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int rdma_get_recv_comp(struct rdma_cm_id *id, struct ibv_wc *wc)
{
	struct ibv_cq *cq;
	void *context;
	int ret;

	do {
		// 轮训接收完成队列
		ret = ibv_poll_cq(id->recv_cq, 1, wc);
		if (ret) break;
		// 请求通知完成队列
		ret = ibv_req_notify_cq(id->recv_cq, 0);
		if (ret) return rdma_seterrno(ret);
		// 轮训接收完成队列
		ret = ibv_poll_cq(id->recv_cq, 1, wc);
		if (ret) break;
		// 获取完成队列事件
		ret = ibv_get_cq_event(id->recv_cq_channel, &cq, &context);
		if (ret) return ret;
		assert(cq == id->recv_cq && context == id);
		// 确认完成队列事件
		ibv_ack_cq_events(id->recv_cq, 1);
	} while (1);
	return (ret < 0) ? rdma_seterrno(ret) : ret;
}
```

#### 3.16.4 提交发送请求

`rdma_post_send`提交发送请求，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int
rdma_post_send(struct rdma_cm_id *id, void *context, void *addr,
	       size_t length, struct ibv_mr *mr, int flags)
{
	struct ibv_sge sge;
	// 设置SGE
	sge.addr = (uint64_t) (uintptr_t) addr;
	sge.length = (uint32_t) length;
	sge.lkey = mr ? mr->lkey : 0;
	// 提交发送请求
	return rdma_post_sendv(id, context, &sge, 1, flags);
}
```

`rdma_post_sendv`提交发送请求到QP，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int
rdma_post_sendv(struct rdma_cm_id *id, void *context, struct ibv_sge *sgl, int nsge, int flags)
{
	struct ibv_send_wr wr, *bad;
	// 设置WR
	wr.wr_id = (uintptr_t) context;
	wr.next = NULL;
	wr.sg_list = sgl;
	wr.num_sge = nsge;
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = flags;
	// 提交发送请求
	return rdma_seterrno(ibv_post_send(id->qp, &wr, &bad));
}
```

#### 3.16.5 等待发送完成

`rdma_get_send_comp`等待轮训完成队列，等待发送完成，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int rdma_get_send_comp(struct rdma_cm_id *id, struct ibv_wc *wc)
{
	struct ibv_cq *cq;
	void *context;
	int ret;

	do {
		// 轮训发送完成队列
		ret = ibv_poll_cq(id->send_cq, 1, wc);
		if (ret) break;
		// 请求通知完成队列
		ret = ibv_req_notify_cq(id->send_cq, 0);
		if (ret) return rdma_seterrno(ret);
		// 轮训发送完成队列
		ret = ibv_poll_cq(id->send_cq, 1, wc);
		if (ret) break;
		// 获取完成队列事件
		ret = ibv_get_cq_event(id->send_cq_channel, &cq, &context);
		if (ret) return ret;
		// 确认完成队列事件
		assert(cq == id->send_cq && context == id);
		ibv_ack_cq_events(id->send_cq, 1);
	} while (1);
	return (ret < 0) ? rdma_seterrno(ret) : ret;
}
```

#### 3.16.6 注销MR

在数据交换完成后，`rdma_dereg_mr`注销MR，如下：

```c
// file: rdma-core/librdmacm/rdma_verbs.h
static inline int rdma_dereg_mr(struct ibv_mr *mr)
{
	return rdma_seterrno(ibv_dereg_mr(mr));
}
```

### 3.17 CM DISCONNECT

在服务端和客户端处理完成后，通过`rdma_disconnect`断开连接，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
	// 创建监听端点
	ret = rdma_create_ep(&listen_id, res, NULL, &init_attr);
	if (ret) { ... }
	// 监听端口
	ret = rdma_listen(listen_id, 0);
	...
	// 获取连接请求
	ret = rdma_get_request(listen_id, &id);
	...
	// 接受连接请求
	ret = rdma_accept(id, NULL);
	...
out_disconnect:
	// 断开连接
	rdma_disconnect(id);
}
```

#### 3.17.1 用户空间DISCONNECT

`rdma_disconnect`通过`DISCONNECT`命令和内核空间进行交互，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_disconnect(struct rdma_cm_id *id)
{
	struct ucma_abi_disconnect cmd;
	struct cma_id_private *id_priv;
	int ret;

	// 关闭QP
	ret = ucma_shutdown(id);
	if (ret) return ret;

	// 初始化`DISCONNECT`命令
	CMA_INIT_CMD(&cmd, sizeof cmd, DISCONNECT);
	id_priv = container_of(id, struct cma_id_private, id);
	cmd.id = id_priv->handle;

	ret = write(id->channel->fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;
	// 完成连接断开
	return ucma_complete(id);
}
```

`ucma_shutdown`关闭QP，如下：

```c
// file: rdma-core/librdmacm/cma.c
int ucma_shutdown(struct rdma_cm_id *id)
{
	if (!id->verbs || !id->verbs->device)
		return ERR(EINVAL);

	switch (id->verbs->device->transport_type) {
	case IBV_TRANSPORT_IB:
		// 修改QP为错误状态
		return ucma_modify_qp_err(id);
	case IBV_TRANSPORT_IWARP:
		// 修改QP为SQD状态
		return ucma_modify_qp_sqd(id);
	default:
		return ERR(EINVAL);
	}
}
```

#### 3.17.2 内核空间处理DISCONNECT

`DISCONNECT`命令用于断开对端cm id的连接，对应的处理函数为`ucma_disconnect`，如下：

```c
// file: drivers/infiniband/core/ucma.c
static ssize_t ucma_disconnect(struct ucma_file *file, const char __user *inbuf,
			       int in_len, int out_len)
{
	struct rdma_ucm_disconnect cmd;
	struct ucma_context *ctx;
	int ret;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;
	ctx = ucma_get_ctx_dev(file, cmd.id);
	if (IS_ERR(ctx)) return PTR_ERR(ctx);

	mutex_lock(&ctx->mutex);
	// 断开连接
	ret = rdma_disconnect(ctx->cm_id);
	mutex_unlock(&ctx->mutex);
	ucma_put_ctx(ctx);
	return ret;
}
```

`rdma_disconnect`断开连接，如下：

```c
// file: drivers/infiniband/core/cma.c
int rdma_disconnect(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!id_priv->cm_id.ib) return -EINVAL;

	if (rdma_cap_ib_cm(id->device, id->port_num)) {
		// 修改QP为错误状态
		ret = cma_modify_qp_err(id_priv);
		if (ret) goto out;
		trace_cm_disconnect(id_priv);
		// 发送DISCONNECT请求
		if (ib_send_cm_dreq(id_priv->cm_id.ib, NULL, 0)) {
			// 发送DISCONNECT响应
			if (!ib_send_cm_drep(id_priv->cm_id.ib, NULL, 0))
				trace_cm_sent_drep(id_priv);
		} else {
			trace_cm_sent_dreq(id_priv);
		}
	} else if (rdma_cap_iw_cm(id->device, id->port_num)) {
		// iwarp断开连接
		ret = iw_cm_disconnect(id_priv->cm_id.iw, 0);
	} else
		ret = -EINVAL;
out:
	return ret;
}
```

### 3.18 CM销毁端点

在服务端和客户端处理完成后，通过`rdma_destroy_ep`销毁端点，如下：

```c
// file: rdma-core/librdmacm/examples/rdma_server.c
static int run(void)
{
	...
out_destroy_accept_ep:
	rdma_destroy_ep(id);
out_destroy_listen_ep:
	rdma_destroy_ep(listen_id);
	...
}
```

#### 3.18.1 用户空间销毁端点

`rdma_destroy_ep`销毁端点，如下：

```c
// file: rdma-core/librdmacm/cma.c
void rdma_destroy_ep(struct rdma_cm_id *id)
{
	struct cma_id_private *id_priv;
	// 销毁QP
	if (id->qp) rdma_destroy_qp(id);
	// 销毁SRQ
	if (id->srq) rdma_destroy_srq(id);

	id_priv = container_of(id, struct cma_id_private, id);
	if (id_priv->qp_init_attr)
		free(id_priv->qp_init_attr);
	// 销毁ID
	rdma_destroy_id(id);
}
```

##### 1. 销毁QP

`rdma_destroy_qp`销毁QP，如下：

```c
// file: rdma-core/librdmacm/cma.c
void rdma_destroy_qp(struct rdma_cm_id *id)
{
	ibv_destroy_qp(id->qp);
	id->qp = NULL;
	ucma_destroy_cqs(id);
}
```

`ucma_destroy_cqs`销毁CQ，如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_destroy_cqs(struct rdma_cm_id *id)
{
	if (id->qp_type == IBV_QPT_XRC_RECV && id->srq) return;

	if (id->recv_cq) {
		// 销毁接收CQ
		ibv_destroy_cq(id->recv_cq);
		if (id->send_cq && (id->send_cq != id->recv_cq)) {
			// 销毁发送CQ
			ibv_destroy_cq(id->send_cq);
			id->send_cq = NULL;
		}
		id->recv_cq = NULL;
	}
	if (id->recv_cq_channel) {
		// 销毁接收CQ通道
		ibv_destroy_comp_channel(id->recv_cq_channel);
		if (id->send_cq_channel && (id->send_cq_channel != id->recv_cq_channel)) {
			// 销毁发送CQ通道
			ibv_destroy_comp_channel(id->send_cq_channel);
			id->send_cq_channel = NULL;
		}
		id->recv_cq_channel = NULL;
	}
}
```

##### 2. 销毁CM ID

`rdma_destroy_id`销毁CM ID，如下：

```c
// file: rdma-core/librdmacm/cma.c
int rdma_destroy_id(struct rdma_cm_id *id)
{
	struct cma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct cma_id_private, id);
	// 销毁内核ID
	ret = ucma_destroy_kern_id(id->channel->fd, id_priv->handle);
	if (ret < 0) return ret;

	if (id_priv->id.event)
		rdma_ack_cm_event(id_priv->id.event);

	pthread_mutex_lock(&id_priv->mut);
	while (id_priv->events_completed < ret)
		pthread_cond_wait(&id_priv->cond, &id_priv->mut);
	pthread_mutex_unlock(&id_priv->mut);
	// 释放ID私有结构体
	ucma_free_id(id_priv);
	return 0;
}
```

##### 3. 销毁内核ID

`ucma_destroy_kern_id`销毁内核ID，如下：

```c
// file: rdma-core/librdmacm/cma.c
static int ucma_destroy_kern_id(int fd, uint32_t handle)
{
	struct ucma_abi_destroy_id_resp resp;
	struct ucma_abi_destroy_id cmd;
	int ret;

	// 初始化`DESTROY_ID`命令
	CMA_INIT_CMD_RESP(&cmd, sizeof cmd, DESTROY_ID, &resp, sizeof resp);
	cmd.id = handle;

	ret = write(fd, &cmd, sizeof cmd);
	if (ret != sizeof cmd)
		return (ret >= 0) ? ERR(ENODATA) : -1;

	VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);
	return resp.events_reported;
}
```

##### 4. 销毁用户ID

`ucma_free_id`释放ID私有结构体，如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_free_id(struct cma_id_private *id_priv)
{
	// 从设备中移除ID
	ucma_remove_id(id_priv);
	if (id_priv->cma_dev)
		// 释放设备
		ucma_put_device(id_priv->cma_dev);
	pthread_cond_destroy(&id_priv->cond);
	pthread_mutex_destroy(&id_priv->mut);
	if (id_priv->id.route.path_rec)
		free(id_priv->id.route.path_rec);

	if (id_priv->sync)
		// 销毁事件通道
		rdma_destroy_event_channel(id_priv->id.channel);
	if (id_priv->connect_len)
		free(id_priv->connect);
	if (id_priv->resolved_ai)
		rdma_freeaddrinfo(id_priv->resolved_ai);
	free(id_priv);
}
```

`ucma_put_device`释放设备，如下：

```c
// file: rdma-core/librdmacm/cma.c
static void ucma_put_device(struct cma_device *cma_dev)
{
	pthread_mutex_lock(&mut);
	if (!--cma_dev->refcnt) {
		// 释放PD
		ibv_dealloc_pd(cma_dev->pd);
		if (cma_dev->xrcd)
			ibv_close_xrcd(cma_dev->xrcd);
		cma_dev->pd = NULL;
		cma_dev->xrcd = NULL;
		if (cma_dev->is_device_dead)
			// 从设备列表中移除设备
			remove_cma_dev(cma_dev);
	}
	pthread_mutex_unlock(&mut);
}
```

##### 5. 移除设备

`remove_cma_dev`从设备列表中移除设备，如下：

```c
// file: rdma-core/librdmacm/cma.c
static void remove_cma_dev(struct cma_device *cma_dev)
{
	if (cma_dev->refcnt) {
		// 引用计数不为0，说明有ID在使用该设备
		cma_dev->is_device_dead = true;
		return;
	}
	// 关闭XRC
	if (cma_dev->xrcd) ibv_close_xrcd(cma_dev->xrcd);
	// 释放PD
	if (cma_dev->pd) ibv_dealloc_pd(cma_dev->pd);
	// 关闭设备
	if (cma_dev->verbs) ibv_close_device(cma_dev->verbs);
	// 释放端口
	free(cma_dev->port);
	// 从设备列表中移除设备
	list_del_from(&cma_dev_list, &cma_dev->entry);
	// 释放设备结构体
	free(cma_dev);
}
```

### 3.19 CM内部的实现过程

在上面的章节中，我们介绍了LISTEN,CONNECT,ACCEPT和DISCONNECT的实现过程，下面我们来分析通过CM内部的实现过程。CM通过`mad_client`和`cm_client`来实现管理的，分别在`ib_mad_init`和`ib_cm_init`中注册，如下：

#### 3.19.1 MAD Client

`mad_client`是一个IB客户端，用于发送和接收MAD消息，定义如下：

```c
// file: drivers/infiniband/core/mad.c
static struct ib_client mad_client = {
	.name   = "mad",
	.add = ib_mad_init_device,
	.remove = ib_mad_remove_device
};
```

`ib_mad_init`注册`mad_client`，如下：

```c
// file: drivers/infiniband/core/mad.c
int ib_mad_init(void)
{
	// 初始化recvq和sendq大小
	mad_recvq_size = min(mad_recvq_size, IB_MAD_QP_MAX_SIZE);
	mad_recvq_size = max(mad_recvq_size, IB_MAD_QP_MIN_SIZE);

	mad_sendq_size = min(mad_sendq_size, IB_MAD_QP_MAX_SIZE);
	mad_sendq_size = max(mad_sendq_size, IB_MAD_QP_MIN_SIZE);

	INIT_LIST_HEAD(&ib_mad_port_list);
	// 注册mad client
	if (ib_register_client(&mad_client)) {
		pr_err("Couldn't register ib_mad client\n");
		return -EINVAL;
	}
	return 0;
}
void ib_mad_cleanup(void)
{
	// 注销mad client
	ib_unregister_client(&mad_client);
}
```

##### 1. 打开MAD端口

`mad_client`设置的`.add`接口是`ib_mad_init_device`，如下：

```c
// file: drivers/infiniband/core/mad.c
static int ib_mad_init_device(struct ib_device *device)
{
	int start, i;
	unsigned int count = 0;
	int ret;

	start = rdma_start_port(device);
	// 遍历所有端口
	for (i = start; i <= rdma_end_port(device); i++) {
		// 检查是否支持MAD
		if (!rdma_cap_ib_mad(device, i)) continue;
		// 打开MAD端口
		ret = ib_mad_port_open(device, i);
		if (ret) { ... }
		// 打开agent端口
		ret = ib_agent_port_open(device, i);
		if (ret) { ... }
		count++;
	}
	if (!count)return -EOPNOTSUPP;
	return 0;
	...
}
```

* 创建QP,PD,MR和CQ

`ib_mad_port_open`函数用于打开MAD端口，创建QP,PD,MR和CQ。如下：

```c
// file: drivers/infiniband/core/mad.c
static int ib_mad_port_open(struct ib_device *device, u32 port_num)
{
	int ret, cq_size;
	struct ib_mad_port_private *port_priv;
	unsigned long flags;
	int has_smi;

	if (WARN_ON(rdma_max_mad_size(device, port_num) < IB_MGMT_MAD_SIZE))
		return -EFAULT;
	if (WARN_ON(rdma_cap_opa_mad(device, port_num) &&
		    rdma_max_mad_size(device, port_num) < OPA_MGMT_MAD_SIZE))
		return -EFAULT;

	// 创建新的mad端口
	port_priv = kzalloc_obj(*port_priv);
	if (!port_priv) return -ENOMEM;

	port_priv->device = device;
	port_priv->port_num = port_num;
	spin_lock_init(&port_priv->reg_lock);
	init_mad_qp(port_priv, &port_priv->qp_info[0]);
	init_mad_qp(port_priv, &port_priv->qp_info[1]);

	// 计算CQ大小
	cq_size = mad_sendq_size + mad_recvq_size;
	has_smi = rdma_cap_ib_smi(device, port_num);
	if (has_smi) cq_size *= 2;

	// 创建PD
	port_priv->pd = ib_alloc_pd(device, 0);
	if (IS_ERR(port_priv->pd)) { ... }
	// 创建CQ
	port_priv->cq = ib_alloc_cq(port_priv->device, port_priv, cq_size, 0,
			IB_POLL_UNBOUND_WORKQUEUE);
	if (IS_ERR(port_priv->cq)) { ... }

	if (has_smi) {
		// 创建SMI QP
		ret = create_mad_qp(&port_priv->qp_info[0], IB_QPT_SMI);
		if (ret) goto error6;
	}

	if (rdma_cap_ib_cm(device, port_num)) {
		// 创建GSI QP
		ret = create_mad_qp(&port_priv->qp_info[1], IB_QPT_GSI);
		if (ret) goto error7;
	}
	// 创建工作队列
	port_priv->wq = alloc_ordered_workqueue("ib_mad%u", WQ_MEM_RECLAIM, port_num);
	if (!port_priv->wq) { ... }

	spin_lock_irqsave(&ib_mad_port_list_lock, flags);
	// 将端口添加到列表中
	list_add_tail(&port_priv->port_list, &ib_mad_port_list);
	spin_unlock_irqrestore(&ib_mad_port_list_lock, flags);
	// 开启端口
	ret = ib_mad_port_start(port_priv);
	if (ret) { ... }
	return 0;
	...
}
```

`create_mad_qp`函数用于创建MAD QP，如下：

```c
// file: drivers/infiniband/core/mad.c
static int create_mad_qp(struct ib_mad_qp_info *qp_info, enum ib_qp_type qp_type)
{
	struct ib_qp_init_attr	qp_init_attr;
	int ret;
	// 初始化QP属性
	memset(&qp_init_attr, 0, sizeof qp_init_attr);
	qp_init_attr.send_cq = qp_info->port_priv->cq;
	qp_init_attr.recv_cq = qp_info->port_priv->cq;
	qp_init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	qp_init_attr.cap.max_send_wr = mad_sendq_size;
	qp_init_attr.cap.max_recv_wr = mad_recvq_size;
	qp_init_attr.cap.max_send_sge = IB_MAD_SEND_REQ_MAX_SG;
	qp_init_attr.cap.max_recv_sge = IB_MAD_RECV_REQ_MAX_SG;
	qp_init_attr.qp_type = qp_type;
	qp_init_attr.port_num = qp_info->port_priv->port_num;
	qp_init_attr.qp_context = qp_info;
	qp_init_attr.event_handler = qp_event_handler;
	// 创建QP
	qp_info->qp = ib_create_qp(qp_info->port_priv->pd, &qp_init_attr);
	if (IS_ERR(qp_info->qp)) { ... }
	// 设置最大活跃WR数
	qp_info->send_queue.max_active = mad_sendq_size;
	qp_info->recv_queue.max_active = mad_recvq_size;
	return 0;
error:
	return ret;
}
```

* 提交MAD接收请求

`ib_mad_port_start`函数用于启动MAD端口，提交MAD接收请求。如下：

```c
// file: drivers/infiniband/core/mad.c
static int ib_mad_port_start(struct ib_mad_port_private *port_priv)
{
	int ret, i;
	struct ib_qp_attr *attr;
	struct ib_qp *qp;
	u16 pkey_index;

	attr = kmalloc_obj(*attr);
	if (!attr) return -ENOMEM;
	// 查找pkey索引
	ret = ib_find_pkey(port_priv->device, port_priv->port_num, IB_DEFAULT_PKEY_FULL, &pkey_index);
	if (ret) pkey_index = 0;

	for (i = 0; i < IB_MAD_QPS_CORE; i++) {
		qp = port_priv->qp_info[i].qp;
		if (!qp) continue;

		// 修改QP状态为INIT->RTR->RTS
		attr->qp_state = IB_QPS_INIT;
		attr->pkey_index = pkey_index;
		attr->qkey = (qp->qp_num == 0) ? 0 : IB_QP1_QKEY;
		ret = ib_modify_qp(qp, attr, IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_QKEY);
		if (ret) { ... }

		attr->qp_state = IB_QPS_RTR;
		ret = ib_modify_qp(qp, attr, IB_QP_STATE);
		if (ret) { ... }

		attr->qp_state = IB_QPS_RTS;
		attr->sq_psn = IB_MAD_SEND_Q_PSN;
		ret = ib_modify_qp(qp, attr, IB_QP_STATE | IB_QP_SQ_PSN);
		if (ret) { ... }
	}
	// 请求CQ通知
	ret = ib_req_notify_cq(port_priv->cq, IB_CQ_NEXT_COMP);
	if (ret) { ... }

	for (i = 0; i < IB_MAD_QPS_CORE; i++) {
		if (!port_priv->qp_info[i].qp) continue;
		// 提交MAD接收请求
		ret = ib_mad_post_receive_mads(&port_priv->qp_info[i], NULL);
		if (ret) { ... }
	}
out:
	kfree(attr);
	return ret;
}
```

`ib_mad_post_receive_mads`函数用于提交MAD接收请求，如下：

```c
// file: drivers/infiniband/core/mad.c
static int ib_mad_post_receive_mads(struct ib_mad_qp_info *qp_info, struct ib_mad_private *mad)
{
	unsigned long flags;
	struct ib_mad_private *mad_priv;
	struct ib_sge sg_list;
	struct ib_recv_wr recv_wr;
	// 获取接收队列
	struct ib_mad_queue *recv_queue = &qp_info->recv_queue;
	int ret = 0;

	// 初始化SG列表
	sg_list.lkey = qp_info->port_priv->pd->local_dma_lkey;
	// 初始化接收WR
	recv_wr.next = NULL;
	recv_wr.sg_list = &sg_list;
	recv_wr.num_sge = 1;

	while (true) {
		// 分配并映射接收缓冲区
		if (mad) {
			mad_priv = mad;
			mad = NULL;
		} else {
			mad_priv = alloc_mad_private(port_mad_size(qp_info->port_priv), GFP_ATOMIC);
			if (!mad_priv) return -ENOMEM;
		}
		// 初始化SG列表
		sg_list.length = mad_priv_dma_size(mad_priv);
		sg_list.addr = ib_dma_map_single(qp_info->port_priv->device, &mad_priv->grh,
						 mad_priv_dma_size(mad_priv), DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(qp_info->port_priv->device, sg_list.addr))) { ... }
		mad_priv->header.mapping = sg_list.addr;
		mad_priv->header.mad_list.mad_queue = recv_queue;
		// 设置接收完成的回调函数
		mad_priv->header.mad_list.cqe.done = ib_mad_recv_done;
		recv_wr.wr_cqe = &mad_priv->header.mad_list.cqe;
		spin_lock_irqsave(&recv_queue->lock, flags);
		if (recv_queue->count >= recv_queue->max_active) {
			spin_unlock_irqrestore(&recv_queue->lock, flags);
			break;
		}
		recv_queue->count++;
		list_add_tail(&mad_priv->header.mad_list.list, &recv_queue->list);
		spin_unlock_irqrestore(&recv_queue->lock, flags);
		// 提交接收WR
		ret = ib_post_recv(qp_info->qp, &recv_wr, NULL);
		if (ret) { ... }
	}
	// 释放接收缓冲区
	ib_dma_unmap_single(qp_info->port_priv->device, mad_priv->header.mapping,
			    mad_priv_dma_size(mad_priv), DMA_FROM_DEVICE);
free_mad_priv:
	kfree(mad_priv);
	return ret;
}
```

* 打开agent端口

`ib_agent_port_open`函数注册mad agent端口，如下：

```c
// file: drivers/infiniband/core/agent.c
int ib_agent_port_open(struct ib_device *device, int port_num)
{
	struct ib_agent_port_private *port_priv;
	unsigned long flags;
	int ret;

	// 分配agent端口
	port_priv = kzalloc_obj(*port_priv);
	if (!port_priv) { ... }

	if (rdma_cap_ib_smi(device, port_num)) {
		// 注册SMI MAD agent, 用于发送数据
		port_priv->agent[0] = ib_register_mad_agent(device, port_num, IB_QPT_SMI, NULL, 0,
							    &agent_send_handler, NULL, NULL, 0);
		if (IS_ERR(port_priv->agent[0])) { ... }
	}

	if (rdma_cap_ib_cm(device, port_num)) {
		// 注册GSI MAD agent, 用于发送数据
		port_priv->agent[1] = ib_register_mad_agent(device, port_num, IB_QPT_GSI, NULL, 0,
							    &agent_send_handler, NULL, NULL, 0);
		if (IS_ERR(port_priv->agent[1])) { ... }
	}
	spin_lock_irqsave(&ib_agent_port_list_lock, flags);
	// 添加到`ib_agent_port_list`
	list_add_tail(&port_priv->port_list, &ib_agent_port_list);
	spin_unlock_irqrestore(&ib_agent_port_list_lock, flags);

	return 0;
	....
}
```

##### 2. 关闭MAD端口

`mad_client`设置的`.remove`接口是`ib_mad_remove_device`，如下：

```c
// file: drivers/infiniband/core/mad.c
static void ib_mad_remove_device(struct ib_device *device, void *client_data)
{
	unsigned int i;
	rdma_for_each_port (device, i) {
		// 检查端口是否支持MAD
		if (!rdma_cap_ib_mad(device, i)) continue;
		// 关闭agent端口
		if (ib_agent_port_close(device, i))
			dev_err(&device->dev, "Couldn't close port %u for agents\n", i);
		// 关闭MAD端口
		if (ib_mad_port_close(device, i))
			dev_err(&device->dev, "Couldn't close port %u\n", i);
	}
}
```

`ib_agent_port_close`函数用于关闭agent端口，如下：

```c
// file: drivers/infiniband/core/agent.c
int ib_agent_port_close(struct ib_device *device, int port_num)
{
	struct ib_agent_port_private *port_priv;
	unsigned long flags;

	spin_lock_irqsave(&ib_agent_port_list_lock, flags);
	// 获取agent端口
	port_priv = __ib_get_agent_port(device, port_num);
	if (port_priv == NULL) { ... }
	list_del(&port_priv->port_list);
	spin_unlock_irqrestore(&ib_agent_port_list_lock, flags);

	// 注销agent端口
	if (port_priv->agent[1])
		ib_unregister_mad_agent(port_priv->agent[1]);
	if (port_priv->agent[0])
		ib_unregister_mad_agent(port_priv->agent[0]);

	kfree(port_priv);
	return 0;
}
```

`ib_mad_port_close`函数用于关闭MAD端口，如下：

```c
// file: drivers/infiniband/core/mad.c
static int ib_mad_port_close(struct ib_device *device, u32 port_num)
{
	struct ib_mad_port_private *port_priv;
	unsigned long flags;

	spin_lock_irqsave(&ib_mad_port_list_lock, flags);
	// 获取MAD端口
	port_priv = __ib_get_mad_port(device, port_num);
	if (port_priv == NULL) { ... }
	list_del_init(&port_priv->port_list);
	spin_unlock_irqrestore(&ib_mad_port_list_lock, flags);

	// 销毁工作队列
	destroy_workqueue(port_priv->wq);
	destroy_mad_qp(&port_priv->qp_info[1]);
	destroy_mad_qp(&port_priv->qp_info[0]);
	// 释放CQ
	ib_free_cq(port_priv->cq);
	// 释放PD
	ib_dealloc_pd(port_priv->pd);
	// 清理接收队列
	cleanup_recv_queue(&port_priv->qp_info[1]);
	cleanup_recv_queue(&port_priv->qp_info[0]);

	kfree(port_priv);
	return 0;
}
```

#### 3.19.2 CM Client

`cm_client`同样是一个IB客户端，用于CM的管理，定义如下：

```c
// file: drivers/infiniband/core/cm.c
static struct ib_client cm_client = {
	.name   = "cm",
	.add    = cm_add_one,
	.remove = cm_remove_one
};
```

`ib_cm_init`注册`cm_client`，如下：

```c
// file: drivers/infiniband/core/cm.c
static int __init ib_cm_init(void)
{
	int ret;

	INIT_LIST_HEAD(&cm.device_list);
	rwlock_init(&cm.device_lock);
	spin_lock_init(&cm.lock);
	// 初始化listen service table
	cm.listen_service_table = RB_ROOT;
	cm.listen_service_id = be64_to_cpu(IB_CM_ASSIGN_SERVICE_ID);
	cm.remote_id_table = RB_ROOT;
	cm.remote_qp_table = RB_ROOT;
	cm.remote_sidr_table = RB_ROOT;
	xa_init_flags(&cm.local_id_table, XA_FLAGS_ALLOC);
	// 初始化随机数种子
	get_random_bytes(&cm.random_id_operand, sizeof cm.random_id_operand);
	INIT_LIST_HEAD(&cm.timewait_list);

	cm.wq = alloc_workqueue("ib_cm", WQ_PERCPU, 1);
	if (!cm.wq) { ... }
	// 注册cm client
	ret = ib_register_client(&cm_client);
	if (ret) goto error3;
	return 0;
error3:
	destroy_workqueue(cm.wq);
error2:
	return ret;
}

static void __exit ib_cm_cleanup(void)
{
	struct cm_timewait_info *timewait_info, *tmp;

	spin_lock_irq(&cm.lock);
	list_for_each_entry(timewait_info, &cm.timewait_list, list)
		cancel_delayed_work(&timewait_info->work.work);
	spin_unlock_irq(&cm.lock);
	// 注销cm client
	ib_unregister_client(&cm_client);
	destroy_workqueue(cm.wq);
	list_for_each_entry_safe(timewait_info, tmp, &cm.timewait_list, list) {
		list_del(&timewait_info->list);
		kfree(timewait_info);
	}
	WARN_ON(!xa_empty(&cm.local_id_table));
}
module_init(ib_cm_init);
module_exit(ib_cm_cleanup);
```

##### 1. 添加CM连接

`cm_client`设置的`.add`接口是`cm_add_one`，如下：

```c
// file: drivers/infiniband/core/cm.c
static int cm_add_one(struct ib_device *ib_device)
{
	struct cm_device *cm_dev;
	struct cm_port *port;
	struct ib_mad_reg_req reg_req = {
		.mgmt_class = IB_MGMT_CLASS_CM,
		.mgmt_class_version = IB_CM_CLASS_VERSION,
	};
	struct ib_port_modify port_modify = {
		.set_port_cap_mask = IB_PORT_CM_SUP
	};
	....

	// 创建cm设备
	cm_dev = kzalloc_flex(*cm_dev, port, ib_device->phys_port_cnt);
	if (!cm_dev) return -ENOMEM;

	kref_init(&cm_dev->kref);
	rwlock_init(&cm_dev->mad_agent_lock);
	cm_dev->ib_device = ib_device;
	cm_dev->ack_delay = ib_device->attrs.local_ca_ack_delay;
	cm_dev->going_down = 0;
	// 设置cm设备的client data
	ib_set_client_data(ib_device, &cm_client, cm_dev);

	set_bit(IB_MGMT_METHOD_SEND, reg_req.method_mask);
	rdma_for_each_port (ib_device, i) {
		// 检查端口是否支持CM
		if (!rdma_cap_ib_cm(ib_device, i)) continue;

		port = kzalloc_obj(*port);
		if (!port) { ... }
		// 初始化cm端口
		cm_dev->port[i-1] = port;
		port->cm_dev = cm_dev;
		port->port_num = i;
		// 注册cm端口的client groups
		ret = ib_port_register_client_groups(ib_device, i, cm_counter_groups);
		if (ret) goto error1;

		// 注册cm端口的mad agent
		port->mad_agent = ib_register_mad_agent(ib_device, i, IB_QPT_GSI, &reg_req, 0,
							cm_send_handler, cm_recv_handler, port, 0);
		if (IS_ERR(port->mad_agent)) { ... }

		// 注册cm端口的rep agent
		port->rep_agent = ib_register_mad_agent(ib_device, i, IB_QPT_GSI, NULL, 0,
							cm_send_handler, NULL, port, 0);
		if (IS_ERR(port->rep_agent)) { ... }
		// 修改端口，使端口支持CM
		ret = ib_modify_port(ib_device, i, 0, &port_modify);
		if (ret) goto error4;

		count++;
	}
	if (!count) { ... }
	write_lock_irqsave(&cm.device_lock, flags);
	// 添加cm设备到cm设备列表
	list_add_tail(&cm_dev->list, &cm.device_list);
	write_unlock_irqrestore(&cm.device_lock, flags);
	return 0;
	...
}
```

##### 2. 删除CM连接

`cm_client`设置的`.remove`接口是`cm_remove_one`，如下：

```c
// file: drivers/infiniband/core/cm.c
static void cm_remove_one(struct ib_device *ib_device, void *client_data)
{
	struct cm_device *cm_dev = client_data;
	struct cm_port *port;
	struct ib_port_modify port_modify = {
		.clr_port_cap_mask = IB_PORT_CM_SUP
	};
	unsigned long flags;
	u32 i;

	write_lock_irqsave(&cm.device_lock, flags);
	list_del(&cm_dev->list);
	write_unlock_irqrestore(&cm.device_lock, flags);

	spin_lock_irq(&cm.lock);
	cm_dev->going_down = 1;
	spin_unlock_irq(&cm.lock);

	rdma_for_each_port (ib_device, i) {
		struct ib_mad_agent *mad_agent;
		struct ib_mad_agent *rep_agent;

		if (!rdma_cap_ib_cm(ib_device, i)) continue;

		port = cm_dev->port[i-1];
		mad_agent = port->mad_agent;
		rep_agent = port->rep_agent;
		// 修改端口，使端口不支持CM
		ib_modify_port(ib_device, port->port_num, 0, &port_modify);

		flush_workqueue(cm.wq);
		write_lock(&cm_dev->mad_agent_lock);
		port->mad_agent = NULL;
		port->rep_agent = NULL;
		write_unlock(&cm_dev->mad_agent_lock);
		// 注销cm端口的mad agent和rep agent
		ib_unregister_mad_agent(mad_agent);
		ib_unregister_mad_agent(rep_agent);
		ib_port_unregister_client_groups(ib_device, i, cm_counter_groups);
	}
	cm_device_put(cm_dev);
}
```

#### 3.19.3 MAD Agent的实现

##### 1. 注册Agent

`mad_client`和`cm_client`都通过`ib_register_mad_agent`注册mad agent, 如下：

```c
// file: drivers/infiniband/core/mad.c
struct ib_mad_agent *ib_register_mad_agent(struct ib_device *device,
					   u32 port_num,
					   enum ib_qp_type qp_type,
					   struct ib_mad_reg_req *mad_reg_req,
					   u8 rmpp_version,
					   ib_mad_send_handler send_handler,
					   ib_mad_recv_handler recv_handler,
					   void *context,
					   u32 registration_flags)
{
	struct ib_mad_port_private *port_priv;
	struct ib_mad_agent *ret = ERR_PTR(-EINVAL);
	struct ib_mad_agent_private *mad_agent_priv;
	struct ib_mad_reg_req *reg_req = NULL;
	struct ib_mad_mgmt_class_table *class;
	struct ib_mad_mgmt_vendor_class_table *vendor;
	struct ib_mad_mgmt_vendor_class *vendor_class;
	struct ib_mad_mgmt_method_table *method;
	int ret2, qpn;
	u8 mgmt_class, vclass;

	// 检查QP类型是否匹配
	if ((qp_type == IB_QPT_SMI && !rdma_cap_ib_smi(device, port_num)) ||
	    (qp_type == IB_QPT_GSI && !rdma_cap_ib_cm(device, port_num)))
		return ERR_PTR(-EPROTONOSUPPORT);

	// 验证参数
	qpn = get_spl_qp_index(qp_type);
	if (qpn == -1) { ... }
	...

	// 获取mad端口
	port_priv = ib_get_mad_port(device, port_num);
	if (!port_priv) { ... }

	// 分配mad agent private结构
	mad_agent_priv = kzalloc_obj(*mad_agent_priv);
	if (!mad_agent_priv) { ... }

	if (mad_reg_req) {
		reg_req = kmemdup(mad_reg_req, sizeof *reg_req, GFP_KERNEL);
		if (!reg_req) { ... }
	}

	// 填充字段
	mad_agent_priv->qp_info = &port_priv->qp_info[qpn];
	mad_agent_priv->reg_req = reg_req;
	mad_agent_priv->agent.rmpp_version = rmpp_version;
	mad_agent_priv->agent.device = device;
	mad_agent_priv->agent.recv_handler = recv_handler;
	mad_agent_priv->agent.send_handler = send_handler;
	mad_agent_priv->agent.context = context;
	mad_agent_priv->agent.qp = port_priv->qp_info[qpn].qp;
	mad_agent_priv->agent.port_num = port_num;
	mad_agent_priv->agent.flags = registration_flags;
	spin_lock_init(&mad_agent_priv->lock);
	INIT_LIST_HEAD(&mad_agent_priv->send_list);
	INIT_LIST_HEAD(&mad_agent_priv->wait_list);
	INIT_LIST_HEAD(&mad_agent_priv->rmpp_list);
	INIT_LIST_HEAD(&mad_agent_priv->backlog_list);
	INIT_DELAYED_WORK(&mad_agent_priv->timed_work, timeout_sends);
	INIT_LIST_HEAD(&mad_agent_priv->local_list);
	INIT_WORK(&mad_agent_priv->local_work, local_completions);
	refcount_set(&mad_agent_priv->refcount, 1);
	init_completion(&mad_agent_priv->comp);
	mad_agent_priv->sol_fc_send_count = 0;
	mad_agent_priv->sol_fc_wait_count = 0;
	mad_agent_priv->sol_fc_max = recv_handler ? get_sol_fc_max_outstanding(mad_reg_req) : 0;

	ret2 = ib_mad_agent_security_setup(&mad_agent_priv->agent, qp_type);
	if (ret2) { ... }

	// 添加到`ib_mad_clients`
	ret2 = xa_alloc_cyclic(&ib_mad_clients, &mad_agent_priv->agent.hi_tid,
			mad_agent_priv, XA_LIMIT(0, (1 << 24) - 1),
			&ib_mad_client_next, GFP_KERNEL);
	if (ret2 < 0) { ... }

	...

	trace_ib_mad_create_agent(mad_agent_priv);
	return &mad_agent_priv->agent;
}
```

##### 2. 注销Agent

`unregister_mad_agent`注销mad agent, 如下：

```c
// file: drivers/infiniband/core/mad.c
static void unregister_mad_agent(struct ib_mad_agent_private *mad_agent_priv)
{
	struct ib_mad_port_private *port_priv;

	trace_ib_mad_unregister_agent(mad_agent_priv);

	// 取消所有发送
	cancel_mads(mad_agent_priv);
	port_priv = mad_agent_priv->qp_info->port_priv;
	cancel_delayed_work(&mad_agent_priv->timed_work);

	spin_lock_irq(&port_priv->reg_lock);
	remove_mad_reg_req(mad_agent_priv);
	spin_unlock_irq(&port_priv->reg_lock);
	xa_erase(&ib_mad_clients, mad_agent_priv->agent.hi_tid);

	flush_workqueue(port_priv->wq);

	deref_mad_agent(mad_agent_priv);
	// 等待所有完成
	wait_for_completion(&mad_agent_priv->comp);
	ib_cancel_rmpp_recvs(mad_agent_priv);

	ib_mad_agent_security_cleanup(&mad_agent_priv->agent);

	kfree(mad_agent_priv->reg_req);
	kfree_rcu(mad_agent_priv, rcu);
}
```

##### 3. Agent的本地执行过程

`agent`本地的mad通过wq执行，设置的执行接口为`local_completions`，如下：

```c
// file: drivers/infiniband/core/mad.c
static void local_completions(struct work_struct *work)
{
	struct ib_mad_agent_private *mad_agent_priv;
	struct ib_mad_local_private *local;
	struct ib_mad_agent_private *recv_mad_agent;
	unsigned long flags;
	int free_mad;
	struct ib_wc wc;
	struct ib_mad_send_wc mad_send_wc;
	bool opa;

	mad_agent_priv = container_of(work, struct ib_mad_agent_private, local_work);
	// 获取是否支持OPA
	opa = rdma_cap_opa_mad(mad_agent_priv->qp_info->port_priv->device,
			       mad_agent_priv->qp_info->port_priv->port_num);

	spin_lock_irqsave(&mad_agent_priv->lock, flags);
	while (!list_empty(&mad_agent_priv->local_list)) {
		// 获取本地完成
		local = list_entry(mad_agent_priv->local_list.next, struct ib_mad_local_private, completion_list);
		list_del(&local->completion_list);
		spin_unlock_irqrestore(&mad_agent_priv->lock, flags);
		free_mad = 0;
		if (local->mad_priv) {
			u8 base_version;
			// 获取接收mad agent
			recv_mad_agent = local->recv_mad_agent;
			if (!recv_mad_agent) {
				// 没有接收mad agent, 直接完成发送
				dev_err(&mad_agent_priv->agent.device->dev, "No receive MAD agent for local completion\n");
				free_mad = 1;
				goto local_send_completion;
			}
			// 构建SMP完成状态
			build_smp_wc(recv_mad_agent->agent.qp, local->mad_send_wr->send_wr.wr.wr_cqe,
				     be16_to_cpu(IB_LID_PERMISSIVE),
				     local->mad_send_wr->send_wr.pkey_index,
				     recv_mad_agent->agent.port_num, &wc);
			local->mad_priv->header.recv_wc.wc = &wc;
			// 获取发送mad的base version
			base_version = ((struct ib_mad_hdr *)(local->mad_priv->mad))->base_version;
			if (opa && base_version == OPA_MGMT_BASE_VERSION) {
				local->mad_priv->header.recv_wc.mad_len = local->return_wc_byte_len;
				local->mad_priv->header.recv_wc.mad_seg_size = sizeof(struct opa_mad);
			} else {
				local->mad_priv->header.recv_wc.mad_len = sizeof(struct ib_mad);
				local->mad_priv->header.recv_wc.mad_seg_size = sizeof(struct ib_mad);
			}

			INIT_LIST_HEAD(&local->mad_priv->header.recv_wc.rmpp_list);
			list_add(&local->mad_priv->header.recv_wc.recv_buf.list,
				 &local->mad_priv->header.recv_wc.rmpp_list);
			local->mad_priv->header.recv_wc.recv_buf.grh = NULL;
			local->mad_priv->header.recv_wc.recv_buf.mad =
						(struct ib_mad *)local->mad_priv->mad;
			// 调用接收处理函数
			recv_mad_agent->agent.recv_handler(
						&recv_mad_agent->agent,
						&local->mad_send_wr->send_buf,
						&local->mad_priv->header.recv_wc);
			spin_lock_irqsave(&recv_mad_agent->lock, flags);
			deref_mad_agent(recv_mad_agent);
			spin_unlock_irqrestore(&recv_mad_agent->lock, flags);
		}

local_send_completion:
		// 设置发送完成状态
		mad_send_wc.status = IB_WC_SUCCESS;
		mad_send_wc.vendor_err = 0;
		mad_send_wc.send_buf = &local->mad_send_wr->send_buf;
		// 调用发送处理函数
		mad_agent_priv->agent.send_handler(&mad_agent_priv->agent, &mad_send_wc);

		spin_lock_irqsave(&mad_agent_priv->lock, flags);
		deref_mad_agent(mad_agent_priv);
		if (free_mad) kfree(local->mad_priv);
		kfree(local);
	}
	spin_unlock_irqrestore(&mad_agent_priv->lock, flags);
}
```

##### 4. 发送消息的过程

`agent`最终通过`ib_send_mad`发送mad消息，如下:

```c
// file: drivers/infiniband/core/mad.c
int ib_send_mad(struct ib_mad_send_wr_private *mad_send_wr)
{
	struct ib_mad_qp_info *qp_info;
	struct list_head *list;
	struct ib_mad_agent *mad_agent;
	struct ib_sge *sge;
	unsigned long flags;
	int ret;

	// 设置`mad_send_wr`属性
	qp_info = mad_send_wr->mad_agent_priv->qp_info;
	mad_send_wr->mad_list.mad_queue = &qp_info->send_queue;
	mad_send_wr->mad_list.cqe.done = ib_mad_send_done;
	mad_send_wr->send_wr.wr.wr_cqe = &mad_send_wr->mad_list.cqe;

	mad_agent = mad_send_wr->send_buf.mad_agent;
	// 映射mad消息
	sge = mad_send_wr->sg_list;
	sge[0].addr = ib_dma_map_single(mad_agent->device, mad_send_wr->send_buf.mad,
					sge[0].length, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(mad_agent->device, sge[0].addr)))
		return -ENOMEM;

	mad_send_wr->header_mapping = sge[0].addr;
	// 映射payload
	sge[1].addr = ib_dma_map_single(mad_agent->device, ib_get_payload(mad_send_wr),
					sge[1].length, DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(mad_agent->device, sge[1].addr))) { ... }
	mad_send_wr->payload_mapping = sge[1].addr;

	spin_lock_irqsave(&qp_info->send_queue.lock, flags);
	if (qp_info->send_queue.count < qp_info->send_queue.max_active) {
		trace_ib_mad_ib_send_mad(mad_send_wr, qp_info);
		// 提交发送请求
		ret = ib_post_send(mad_agent->qp, &mad_send_wr->send_wr.wr,  NULL);
		list = &qp_info->send_queue.list;
	} else {
		ret = 0;
		list = &qp_info->overflow_list;
	}
	if (!ret) {
		qp_info->send_queue.count++;
		list_add_tail(&mad_send_wr->mad_list.list, list);
	}
	spin_unlock_irqrestore(&qp_info->send_queue.lock, flags);
	if (ret) {
		ib_dma_unmap_single(mad_agent->device, mad_send_wr->header_mapping,
				    sge[0].length, DMA_TO_DEVICE);
		ib_dma_unmap_single(mad_agent->device, mad_send_wr->payload_mapping,
				    sge[1].length, DMA_TO_DEVICE);
	}
	return ret;
}
```

发送完成后，`ib_mad_send_done`会被调用，如下:

```c
// file: drivers/infiniband/core/mad.c
static void ib_mad_send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ib_mad_port_private *port_priv = cq->cq_context;
	struct ib_mad_list_head *mad_list = container_of(wc->wr_cqe, struct ib_mad_list_head, cqe);
	struct ib_mad_send_wr_private	*mad_send_wr, *queued_send_wr;
	struct ib_mad_qp_info		*qp_info;
	struct ib_mad_queue		*send_queue;
	struct ib_mad_send_wc		mad_send_wc;
	unsigned long flags;
	int ret;

	if (list_empty_careful(&port_priv->port_list))
		return;
	if (wc->status != IB_WC_SUCCESS) {
		// 处理发送错误
		if (!ib_mad_send_error(port_priv, wc)) return;
	}

	mad_send_wr = container_of(mad_list, struct ib_mad_send_wr_private, mad_list);
	send_queue = mad_list->mad_queue;
	qp_info = send_queue->qp_info;

	trace_ib_mad_send_done_agent(mad_send_wr->mad_agent_priv);
	trace_ib_mad_send_done_handler(mad_send_wr, wc);

retry:
	ib_dma_unmap_single(mad_send_wr->send_buf.mad_agent->device, mad_send_wr->header_mapping,
			    mad_send_wr->sg_list[0].length, DMA_TO_DEVICE);
	ib_dma_unmap_single(mad_send_wr->send_buf.mad_agent->device, mad_send_wr->payload_mapping,
			    mad_send_wr->sg_list[1].length, DMA_TO_DEVICE);
	queued_send_wr = NULL;
	spin_lock_irqsave(&send_queue->lock, flags);
	list_del(&mad_list->list);

	if (send_queue->count-- > send_queue->max_active) {
		// 移动到发送队列
		mad_list = container_of(qp_info->overflow_list.next, struct ib_mad_list_head, list);
		queued_send_wr = container_of(mad_list, struct ib_mad_send_wr_private, mad_list);
		list_move_tail(&mad_list->list, &send_queue->list);
	}
	spin_unlock_irqrestore(&send_queue->lock, flags);

	mad_send_wc.send_buf = &mad_send_wr->send_buf;
	mad_send_wc.status = wc->status;
	mad_send_wc.vendor_err = wc->vendor_err;
	// 完成发送请求
	ib_mad_complete_send_wr(mad_send_wr, &mad_send_wc);

	if (queued_send_wr) {
		// 重新提交发送请求
		trace_ib_mad_send_done_resend(queued_send_wr, qp_info);
		ret = ib_post_send(qp_info->qp, &queued_send_wr->send_wr.wr, NULL);
		if (ret) { ...  }
	}
}
```

`ib_mad_complete_send_wr`用于完成发送请求，调用`.send_handler`处理发送完成事件。如下：

```c
// file: drivers/infiniband/core/mad.c
void ib_mad_complete_send_wr(struct ib_mad_send_wr_private *mad_send_wr,
			     struct ib_mad_send_wc *mad_send_wc)
{
	struct ib_mad_agent_private	*mad_agent_priv;
	unsigned long			flags;
	int				ret;

	mad_agent_priv = mad_send_wr->mad_agent_priv;
	spin_lock_irqsave(&mad_agent_priv->lock, flags);
	if (ib_mad_kernel_rmpp_agent(&mad_agent_priv->agent)) {
		// 处理RMPP发送完成事件
		ret = ib_process_rmpp_send_wc(mad_send_wr, mad_send_wc);
		if (ret == IB_RMPP_RESULT_CONSUMED) goto done;
	} else
		ret = IB_RMPP_RESULT_UNHANDLED;

	if (mad_send_wr->state == IB_MAD_STATE_CANCELED)
		mad_send_wc->status = IB_WC_WR_FLUSH_ERR;
	else if (mad_send_wr->state == IB_MAD_STATE_SEND_START && mad_send_wr->timeout) {
		// 等待响应
		wait_for_response(mad_send_wr);
		goto done;
	}
	// 从MAD代理中移除发送请求并通知客户端完成
	if (mad_send_wr->state != IB_MAD_STATE_DONE)
		change_mad_state(mad_send_wr, IB_MAD_STATE_DONE);
	adjust_timeout(mad_agent_priv);
	spin_unlock_irqrestore(&mad_agent_priv->lock, flags);

	if (ret == IB_RMPP_RESULT_INTERNAL) {
		ib_rmpp_send_handler(mad_send_wc);
	} else {
		if (mad_send_wr->is_solicited_fc)
			process_backlog_mads(mad_agent_priv);
		mad_agent_priv->agent.send_handler(&mad_agent_priv->agent, mad_send_wc);
	}
	// 释放MAD代理引用
	deref_mad_agent(mad_agent_priv);
	return;
done:
	spin_unlock_irqrestore(&mad_agent_priv->lock, flags);
}
```

##### 5. 接收消息的过程

mad agent设置的接收完成的处理接口为`ib_mad_recv_done`，如下：

```c
// file: drivers/infiniband/core/mad.c
static void ib_mad_recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ib_mad_port_private *port_priv = cq->cq_context;
	struct ib_mad_list_head *mad_list = container_of(wc->wr_cqe, struct ib_mad_list_head, cqe);
	struct ib_mad_qp_info *qp_info;
	struct ib_mad_private_header *mad_priv_hdr;
	struct ib_mad_private *recv, *response = NULL;
	struct ib_mad_agent_private *mad_agent;
	u32 port_num;
	int ret = IB_MAD_RESULT_SUCCESS;
	size_t mad_size;
	u16 resp_mad_pkey_index = 0;
	bool opa;

	if (list_empty_careful(&port_priv->port_list))
		return;

	if (wc->status != IB_WC_SUCCESS) {
		return;
	}
	// 从MAD队列中移除接收请求
	qp_info = mad_list->mad_queue->qp_info;
	dequeue_mad(mad_list);

	opa = rdma_cap_opa_mad(qp_info->port_priv->device, qp_info->port_priv->port_num);

	mad_priv_hdr = container_of(mad_list, struct ib_mad_private_header, mad_list);
	recv = container_of(mad_priv_hdr, struct ib_mad_private, header);
	// 取消DMA映射
	ib_dma_unmap_single(port_priv->device, recv->header.mapping,
			    mad_priv_dma_size(recv), DMA_FROM_DEVICE);

	// 设置接收完成工作完成
	recv->header.wc = *wc;
	recv->header.recv_wc.wc = &recv->header.wc;
	if (opa && ((struct ib_mad_hdr *)(recv->mad))->base_version == OPA_MGMT_BASE_VERSION) {
		recv->header.recv_wc.mad_len = wc->byte_len - sizeof(struct ib_grh);
		recv->header.recv_wc.mad_seg_size = sizeof(struct opa_mad);
	} else {
		recv->header.recv_wc.mad_len = sizeof(struct ib_mad);
		recv->header.recv_wc.mad_seg_size = sizeof(struct ib_mad);
	}
	recv->header.recv_wc.recv_buf.mad = (struct ib_mad *)recv->mad;
	recv->header.recv_wc.recv_buf.grh = &recv->grh;
	// 验证MAD
	if (!validate_mad((const struct ib_mad_hdr *)recv->mad, qp_info, opa))
		goto out;

	trace_ib_mad_recv_done_handler(qp_info, wc, (struct ib_mad_hdr *)recv->mad);

	// 分配响应MAD
	mad_size = recv->mad_size;
	response = alloc_mad_private(mad_size, GFP_KERNEL);
	if (!response) goto out;


	if (rdma_cap_ib_switch(port_priv->device))
		port_num = wc->port_num;
	else
		port_num = port_priv->port_num;

	if (((struct ib_mad_hdr *)recv->mad)->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) {
		// 处理SMI
		if (handle_smi(port_priv, qp_info, wc, port_num, recv, response, opa) == IB_SMI_DISCARD)
			goto out;
	}

	if (port_priv->device->ops.process_mad) {
		// 调用驱动程序处理MAD
		ret = port_priv->device->ops.process_mad(
			port_priv->device, 0, port_priv->port_num, wc,
			&recv->grh, (const struct ib_mad *)recv->mad,
			(struct ib_mad *)response->mad, &mad_size,
			&resp_mad_pkey_index);

		if (opa)
			wc->pkey_index = resp_mad_pkey_index;

		if (ret & IB_MAD_RESULT_SUCCESS) {
			if (ret & IB_MAD_RESULT_CONSUMED)
				goto out;
			if (ret & IB_MAD_RESULT_REPLY) {
				// 发送响应MAD
				agent_send_response((const struct ib_mad_hdr *)response->mad,
						    &recv->grh, wc, port_priv->device,
						    port_num, qp_info->qp->qp_num, mad_size, opa);
				goto out;
			}
		}
	}
	// 查找MAD代理
	mad_agent = find_mad_agent(port_priv, (const struct ib_mad_hdr *)recv->mad);
	if (mad_agent) {
		trace_ib_mad_recv_done_agent(mad_agent);
		// 通知MAD代理接收完成
		ib_mad_complete_recv(mad_agent, &recv->header.recv_wc);
		recv = NULL;
	} else if ((ret & IB_MAD_RESULT_SUCCESS) &&
		   generate_unmatched_resp(recv, response, &mad_size, opa)) {
		// 发送未匹配响应MAD
		agent_send_response((const struct ib_mad_hdr *)response->mad, &recv->grh, wc,
				    port_priv->device, port_num,
				    qp_info->qp->qp_num, mad_size, opa);
	}

out:
	// 提交下一个接收请求
	if (response) {
		ib_mad_post_receive_mads(qp_info, response);
		kfree(recv);
	} else
		ib_mad_post_receive_mads(qp_info, recv);
}
```

`ib_mad_complete_recv`处理mad的请求，如下：

```c
// file: drivers/infiniband/core/mad.c
static void ib_mad_complete_recv(struct ib_mad_agent_private *mad_agent_priv,
				 struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_mad_send_wr_private *mad_send_wr;
	struct ib_mad_send_wc mad_send_wc;
	unsigned long flags;
	bool is_mad_done;
	int ret;

	INIT_LIST_HEAD(&mad_recv_wc->rmpp_list);
	// 验证MAD权限
	ret = ib_mad_enforce_security(mad_agent_priv, mad_recv_wc->wc->pkey_index);
	if (ret) {
		ib_free_recv_mad(mad_recv_wc);
		deref_mad_agent(mad_agent_priv);
		return;
	}
	// 添加到RMPP列表
	list_add(&mad_recv_wc->recv_buf.list, &mad_recv_wc->rmpp_list);
	if (ib_mad_kernel_rmpp_agent(&mad_agent_priv->agent)) {
		// 处理RMPP MAD
		mad_recv_wc = ib_process_rmpp_recv_wc(mad_agent_priv, mad_recv_wc);
		if (!mad_recv_wc) { ... }
	}

	// 完成对应请求
	if (ib_response_mad(&mad_recv_wc->recv_buf.mad->mad_hdr)) {
		spin_lock_irqsave(&mad_agent_priv->lock, flags);
		// 获取发送WR
		mad_send_wr = ib_find_send_mad(mad_agent_priv, mad_recv_wc);
		if (!mad_send_wr) {
			spin_unlock_irqrestore(&mad_agent_priv->lock, flags);
			if (!ib_mad_kernel_rmpp_agent(&mad_agent_priv->agent)
			   && ib_is_mad_class_rmpp(mad_recv_wc->recv_buf.mad->mad_hdr.mgmt_class)
			   && (ib_get_rmpp_flags(&((struct ib_rmpp_mad *)mad_recv_wc->recv_buf.mad)->rmpp_hdr)
					& IB_MGMT_RMPP_FLAG_ACTIVE)) {
				// 调用`.recv_handler`接口处理RMPP MAD
				mad_agent_priv->agent.recv_handler( &mad_agent_priv->agent, NULL, mad_recv_wc);
				deref_mad_agent(mad_agent_priv);
			} else {
				// 释放接收MAD
				ib_free_recv_mad(mad_recv_wc);
				deref_mad_agent(mad_agent_priv);
				return;
			}
		} else {
			ib_mark_mad_done(mad_send_wr);
			is_mad_done = (mad_send_wr->state == IB_MAD_STATE_DONE);
			spin_unlock_irqrestore(&mad_agent_priv->lock, flags);
			// 调用`.recv_handler`接口
			mad_agent_priv->agent.recv_handler( &mad_agent_priv->agent, &mad_send_wr->send_buf, mad_recv_wc);
			deref_mad_agent(mad_agent_priv);

			if (is_mad_done) {
				// 完成发送WR
				mad_send_wc.status = IB_WC_SUCCESS;
				mad_send_wc.vendor_err = 0;
				mad_send_wc.send_buf = &mad_send_wr->send_buf;
				ib_mad_complete_send_wr(mad_send_wr, &mad_send_wc);
			}
		}
	} else {
		// 调用`.recv_handler`接口
		mad_agent_priv->agent.recv_handler(&mad_agent_priv->agent, NULL, mad_recv_wc);
		deref_mad_agent(mad_agent_priv);
	}
}
```

#### 3.19.4 CM Client的处理过程

mad agent设置的`.recv_handler`在接收mad消息时调用，`cm_client`设置的`.recv_handler`为`cm_recv_handler`，其实现如下：

```c
// file: drivers/infiniband/core/cm.c
static void cm_recv_handler(struct ib_mad_agent *mad_agent,
			    struct ib_mad_send_buf *send_buf,
			    struct ib_mad_recv_wc *mad_recv_wc)
{
	struct cm_port *port = mad_agent->context;
	struct cm_work *work;
	enum ib_cm_event_type event;
	bool alt_path = false;
	u16 attr_id;
	int paths = 0;
	int going_down = 0;

	switch (mad_recv_wc->recv_buf.mad->mad_hdr.attr_id) {
	// 根据属性ID判断事件类型
	case CM_REQ_ATTR_ID:
		alt_path = cm_req_has_alt_path((struct cm_req_msg *)mad_recv_wc->recv_buf.mad);
		paths = 1 + (alt_path != 0);
		event = IB_CM_REQ_RECEIVED;
		break;
		...
	default:
		ib_free_recv_mad(mad_recv_wc);
		return;
	}
	// 记录接收事件
	attr_id = be16_to_cpu(mad_recv_wc->recv_buf.mad->mad_hdr.attr_id);
	atomic_long_inc(&port->counters[CM_RECV][attr_id - CM_ATTR_ID_OFFSET]);

	work = kmalloc_flex(*work, path, paths);
	if (!work) { ... }

	// 初始化工作项
	INIT_DELAYED_WORK(&work->work, cm_work_handler);
	work->cm_event.event = event;
	work->mad_recv_wc = mad_recv_wc;
	work->port = port;

	spin_lock_irq(&cm.lock);
	if (!port->cm_dev->going_down)
		queue_delayed_work(cm.wq, &work->work, 0);
	else
		going_down = 1;
	spin_unlock_irq(&cm.lock);
	if (going_down) {
		kfree(work);
		ib_free_recv_mad(mad_recv_wc);
	}
}
```

在转换为本地事件后，调用`cm_work_handler`处理工作项。如下：

```c
// file: drivers/infiniband/core/cm.c
static void cm_work_handler(struct work_struct *_work)
{
	struct cm_work *work = container_of(_work, struct cm_work, work.work);
	int ret;

	switch (work->cm_event.event) {
	// 处理不同事件类型
	case IB_CM_REQ_RECEIVED:
		ret = cm_req_handler(work);
		break;
	case IB_CM_MRA_RECEIVED:
		ret = cm_mra_handler(work);
		break;
		...
	default:
		trace_icm_handler_err(work->cm_event.event);
		ret = -EINVAL;
		break;
	}
	// 释放工作项
	if (ret) cm_free_work(work);
}
```

#### 3.19.5 通过UD建立连接的处理过程

##### 1. IB/ROCE设备监听

服务端通过`rdma_listen`监听指定的服务ID，在CM ID关联IB/ROCE设备时，即：支持`RDMA_CORE_CAP_IB_CM`属性时，通过`cma_ib_listen`进行监听。实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_ib_listen(struct rdma_id_private *id_priv)
{
	struct sockaddr *addr;
	struct ib_cm_id	*id;
	__be64 svc_id;

	addr = cma_src_addr(id_priv);
	// 获取服务
	svc_id = rdma_get_service_id(&id_priv->id, addr);
	// 进行监听
	id = ib_cm_insert_listen(id_priv->id.device, cma_ib_req_handler, svc_id);
	if (IS_ERR(id)) return PTR_ERR(id);
	id_priv->cm_id.ib = id;
	return 0;
}
```

`rdma_get_service_id`获取监听的服务，即通过bind操作设置的，其实现如下：

```c
// file： drivers/infiniband/core/cma.c
__be64 rdma_get_service_id(struct rdma_cm_id *id, struct sockaddr *addr)
{
	if (addr->sa_family == AF_IB)
		return ((struct sockaddr_ib *) addr)->sib_sid;
	return cpu_to_be64(((u64)id->ps << 16) + be16_to_cpu(cma_port(addr)));
}
```

`ib_cm_insert_listen`创建在指定的服务上创建新的监听，在同样的设备上存在相同的服务ID时，则返回该ID。其实现如下：

```c
// file: drivers/infiniband/core/cm.c
struct ib_cm_id *ib_cm_insert_listen(struct ib_device *device, ib_cm_handler cm_handler, __be64 service_id)
{
	struct cm_id_private *listen_id_priv;
	struct cm_id_private *cm_id_priv;
	int err = 0;

	// 提前创建ID
	cm_id_priv = cm_alloc_id_priv(device, cm_handler, NULL);
	if (IS_ERR(cm_id_priv)) return ERR_CAST(cm_id_priv);
	// 初始化监听
	err = cm_init_listen(cm_id_priv, service_id);
	if (err) {
		ib_destroy_cm_id(&cm_id_priv->id);
		return ERR_PTR(err);
	}

	spin_lock_irq(&cm_id_priv->lock);
	// 将ID插入到`listen_service_table`
	listen_id_priv = cm_insert_listen(cm_id_priv, cm_handler);
	if (listen_id_priv != cm_id_priv) {
		// 已经存在相同的ID时，释放分配的ID
		spin_unlock_irq(&cm_id_priv->lock);
		ib_destroy_cm_id(&cm_id_priv->id);
		if (!listen_id_priv) return ERR_PTR(-EINVAL);
		return &listen_id_priv->id;
	}
	// 设置为监听状态
	cm_id_priv->id.state = IB_CM_LISTEN;
	spin_unlock_irq(&cm_id_priv->lock);
	return &cm_id_priv->id;
}
```

`cm_insert_listen`将监听的CM ID插入到`listen_service_table`中，`listen_service_table`使用红黑树，如下:

```c
// file: drivers/infiniband/core/cm.c
static struct cm_id_private *cm_insert_listen(struct cm_id_private *cm_id_priv, ib_cm_handler shared_handler)
{
	// 获取`listen_service_table`
	struct rb_node **link = &cm.listen_service_table.rb_node;
	struct rb_node *parent = NULL;
	struct cm_id_private *cur_cm_id_priv;
	__be64 service_id = cm_id_priv->id.service_id;
	unsigned long flags;

	spin_lock_irqsave(&cm.lock, flags);
	while (*link) {
		parent = *link;
		cur_cm_id_priv = rb_entry(parent, struct cm_id_private, service_node);
		if (cm_id_priv->id.device < cur_cm_id_priv->id.device)
			link = &(*link)->rb_left;
		else if (cm_id_priv->id.device > cur_cm_id_priv->id.device)
			link = &(*link)->rb_right;
		else if (be64_lt(service_id, cur_cm_id_priv->id.service_id))
			link = &(*link)->rb_left;
		else if (be64_gt(service_id, cur_cm_id_priv->id.service_id))
			link = &(*link)->rb_right;
		else {
			// 检查`cm_handler`是否相同
			if (cur_cm_id_priv->id.cm_handler != shared_handler ||
			    cur_cm_id_priv->id.context ||
			    WARN_ON(!cur_cm_id_priv->id.cm_handler)) {
				spin_unlock_irqrestore(&cm.lock, flags);
				return NULL;
			}
			// 存在相同的监听ID
			refcount_inc(&cur_cm_id_priv->refcount);
			cur_cm_id_priv->listen_sharecount++;
			spin_unlock_irqrestore(&cm.lock, flags);
			return cur_cm_id_priv;
		}
	}
	cm_id_priv->listen_sharecount++;
	rb_link_node(&cm_id_priv->service_node, parent, link);
	// 插入到`listen_service_table`
	rb_insert_color(&cm_id_priv->service_node, &cm.listen_service_table);
	spin_unlock_irqrestore(&cm.lock, flags);
	return cm_id_priv;
}
```

##### 2. 客户端建立UD连接

客户端通过`rdma_connect`建立连接，通过`cma_resolve_ib_udp`建立UD连接，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_resolve_ib_udp(struct rdma_id_private *id_priv, struct rdma_conn_param *conn_param)
{
	struct ib_cm_sidr_req_param req;
	struct ib_cm_id	*id;
	void *private_data;
	u8 offset;
	int ret;

	memset(&req, 0, sizeof req);
	offset = cma_user_data_offset(id_priv);
	if (check_add_overflow(offset, conn_param->private_data_len, &req.private_data_len))
		return -EINVAL;
	// 设置私有数据
	if (req.private_data_len) {
		private_data = kzalloc(req.private_data_len, GFP_ATOMIC);
		if (!private_data) return -ENOMEM;
	} else {
		private_data = NULL;
	}
	// 复制私有数据
	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(private_data + offset, conn_param->private_data, conn_param->private_data_len);

	if (private_data) {
		ret = cma_format_hdr(private_data, id_priv);
		if (ret) goto out;
		req.private_data = private_data;
	}
	// 创建cm id
	id = ib_create_cm_id(id_priv->id.device, cma_sidr_rep_handler, id_priv);
	if (IS_ERR(id)) { ret = PTR_ERR(id); goto out; }
	id_priv->cm_id.ib = id;

	// 设置请求参数
	req.path = id_priv->id.route.path_rec;
	req.sgid_attr = id_priv->id.route.addr.dev_addr.sgid_attr;
	// 设置服务id
	req.service_id = rdma_get_service_id(&id_priv->id, cma_dst_addr(id_priv));
	req.timeout_ms = 1 << (CMA_CM_RESPONSE_TIMEOUT - 8);
	req.max_cm_retries = CMA_MAX_CM_RETRIES;

	trace_cm_send_sidr_req(id_priv);
	ret = ib_send_cm_sidr_req(id_priv->cm_id.ib, &req);
	if (ret) { 
		// 失败时，销毁cm id
		ib_destroy_cm_id(id_priv->cm_id.ib);
		id_priv->cm_id.ib = NULL;
	}
out:
	kfree(private_data);
	return ret;
}
```

`ib_send_cm_sidr_req`通过生成请求后和mad消息后，发送msg，如下：

```c
// file: drivers/infiniband/core/cm.c
int ib_send_cm_sidr_req(struct ib_cm_id *cm_id, struct ib_cm_sidr_req_param *param)
{
	struct cm_id_private *cm_id_priv;
	struct ib_mad_send_buf *msg;
	struct cm_av av = {};
	unsigned long flags;
	int ret;

	if (!param->path || (param->private_data &&
	     param->private_data_len > IB_CM_SIDR_REQ_PRIVATE_DATA_SIZE))
		return -EINVAL;

	cm_id_priv = container_of(cm_id, struct cm_id_private, id);
	// 根据连接参数初始化路由信息
	ret = cm_init_av_by_path(param->path, param->sgid_attr, &av);
	if (ret) return ret;

	spin_lock_irqsave(&cm_id_priv->lock, flags);
	cm_move_av_from_path(&cm_id_priv->av, &av);
	cm_id->service_id = param->service_id;
	cm_id_priv->timeout_ms = param->timeout_ms;
	cm_id_priv->max_cm_retries = param->max_cm_retries;
	if (cm_id->state != IB_CM_IDLE) { ... }

	// 分配msg 
	msg = cm_alloc_priv_msg(cm_id_priv, IB_CM_SIDR_REQ_SENT);
	if (IS_ERR(msg)) { ... }

	// 格式化请求
	cm_format_sidr_req((struct cm_sidr_req_msg *)msg->mad, cm_id_priv, param);

	trace_icm_send_sidr_req(&cm_id_priv->id);
	// 提交发送请求
	ret = ib_post_send_mad(msg, NULL);
	if (ret) goto out_free;
	cm_id->state = IB_CM_SIDR_REQ_SENT;
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	return 0;
out_free:
	cm_free_priv_msg(msg);
out_unlock:
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	return ret;
}
```

##### 3. 服务端处理连接请求

客户端发送`sidr_req`请求，设置的标记为`CM_SIDR_REQ_ATTR_ID`, 对应`IB_CM_SIDR_REQ_RECEIVED`状态，服务端在接收该请求后，对应`cm_sidr_req_handler`处理，如下：

```c
// file: drivers/infiniband/core/cm.c
static int cm_sidr_req_handler(struct cm_work *work)
{
	struct cm_id_private *cm_id_priv, *listen_cm_id_priv;
	struct cm_sidr_req_msg *sidr_req_msg;
	struct ib_wc *wc;
	int ret;

	// 创建新的cm id
	cm_id_priv = cm_alloc_id_priv(work->port->cm_dev->ib_device, NULL, NULL);
	if (IS_ERR(cm_id_priv)) return PTR_ERR(cm_id_priv);

	// 记录SGID/SLID，和请求ID
	sidr_req_msg = (struct cm_sidr_req_msg *) work->mad_recv_wc->recv_buf.mad;
	cm_id_priv->id.remote_id = cpu_to_be32(IBA_GET(CM_SIDR_REQ_REQUESTID, sidr_req_msg));
	cm_id_priv->id.service_id = cpu_to_be64(IBA_GET(CM_SIDR_REQ_SERVICEID, sidr_req_msg));
	cm_id_priv->tid = sidr_req_msg->hdr.tid;

	wc = work->mad_recv_wc->wc;
	cm_id_priv->sidr_slid = wc->slid;
	// 初始化`av`，用于响应请求
	ret = cm_init_av_for_response(work->port, work->mad_recv_wc->wc,
				      work->mad_recv_wc->recv_buf.grh, &cm_id_priv->av);
	if (ret) goto out;

	spin_lock_irq(&cm.lock);
	// 插入到远程的sidr列表
	listen_cm_id_priv = cm_insert_remote_sidr(cm_id_priv);
	if (listen_cm_id_priv) { ... }
	cm_id_priv->id.state = IB_CM_SIDR_REQ_RCVD;
	// 查找监听cm id
	listen_cm_id_priv = cm_find_listen(cm_id_priv->id.device, cm_id_priv->id.service_id);
	if (!listen_cm_id_priv) {
		// 没有匹配的监听cm id，发送错误响应
		spin_unlock_irq(&cm.lock);
		ib_send_cm_sidr_rep(&cm_id_priv->id,
				    &(struct ib_cm_sidr_rep_param){ .status = IB_SIDR_UNSUPPORTED });
		goto out; /* No match. */
	}
	spin_unlock_irq(&cm.lock);
	// 设置`cm_handler`和`context`
	cm_id_priv->id.cm_handler = listen_cm_id_priv->id.cm_handler;
	cm_id_priv->id.context = listen_cm_id_priv->id.context;

	// 生成sidr req事件
	cm_format_sidr_req_event(work, cm_id_priv, &listen_cm_id_priv->id);
	ret = cm_id_priv->id.cm_handler(&cm_id_priv->id, &work->cm_event);
	cm_free_work(work);
	cm_deref_id(listen_cm_id_priv);
	if (ret)cm_destroy_id(&cm_id_priv->id, ret);
	return 0;
out:
	ib_destroy_cm_id(&cm_id_priv->id);
	return -EINVAL;
}
```

可以看到，在创建新的cm id后，设置了`cm_id_priv->id.cm_handler`为监听cm id的`cm_handler`，即设置为`cma_ib_req_handler`，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_ib_req_handler(struct ib_cm_id *cm_id, const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *listen_id, *conn_id = NULL;
	struct rdma_cm_event event = {};
	struct cma_req_info req = {};
	struct net_device *net_dev;
	u8 offset;
	int ret;

	// 获取监听cm id
	listen_id = cma_ib_id_from_event(cm_id, ib_event, &req, &net_dev);
	if (IS_ERR(listen_id)) return PTR_ERR(listen_id);

	trace_cm_req_handler(listen_id, ib_event->event);
	// 检查qp类型是否匹配
	if (!cma_ib_check_req_qp_type(&listen_id->id, ib_event)) { ... }

	mutex_lock(&listen_id->handler_mutex);
	// 确定是否为监听状态
	if (READ_ONCE(listen_id->state) != RDMA_CM_LISTEN) { ... }

	offset = cma_user_data_offset(listen_id);
	event.event = RDMA_CM_EVENT_CONNECT_REQUEST;
	if (ib_event->event == IB_CM_SIDR_REQ_RECEIVED) {
		// 创建ud连接
		conn_id = cma_ib_new_udp_id(&listen_id->id, ib_event, net_dev);
		event.param.ud.private_data = ib_event->private_data + offset;
		event.param.ud.private_data_len = IB_CM_SIDR_REQ_PRIVATE_DATA_SIZE - offset;
	} else {
		// 创建RC/UC连接
		conn_id = cma_ib_new_conn_id(&listen_id->id, ib_event, net_dev);
		cma_set_req_event_data(&event, &ib_event->param.req_rcvd, ib_event->private_data, offset);
	}
	// 检查是否成功创建连接
	if (!conn_id) { ... }

	mutex_lock_nested(&conn_id->handler_mutex, SINGLE_DEPTH_NESTING);
	ret = cma_ib_acquire_dev(conn_id, listen_id, &req);
	if (ret) { ... }

	// 客户端和监听的cm id关联
	conn_id->cm_id.ib = cm_id;
	cm_id->context = conn_id;
	// 修改监听的`cm_handler`为`cma_ib_handler`
	cm_id->cm_handler = cma_ib_handler;

	ret = cma_cm_event_handler(conn_id, &event);
	if (ret) { ... }

	// 检查为RC/UC连接时，需要准备MRA
	if (READ_ONCE(conn_id->state) == RDMA_CM_CONNECT && conn_id->id.qp_type != IB_QPT_UD) {
		trace_cm_prepare_mra(cm_id->context);
		ib_prepare_cm_mra(cm_id);
	}
	mutex_unlock(&conn_id->handler_mutex);
err_unlock:
	mutex_unlock(&listen_id->handler_mutex);
net_dev_put:
	dev_put(net_dev);
	return ret;
}
```

##### 4. 创建UD连接

服务端处理连接请求时，通过`cma_ib_new_udp_id`创建新的cm id，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static struct rdma_id_private * cma_ib_new_udp_id(const struct rdma_cm_id *listen_id,
		  const struct ib_cm_event *ib_event, struct net_device *net_dev)
{
	const struct rdma_id_private *listen_id_priv;
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	const sa_family_t ss_family = listen_id->route.addr.src_addr.ss_family;
	struct net *net = listen_id->route.addr.dev_addr.net;
	int ret;

	listen_id_priv = container_of(listen_id, struct rdma_id_private, id);
	// 创建新的cm id
	id_priv = __rdma_create_id(net, listen_id->event_handler, listen_id->context, 
					listen_id->ps, IB_QPT_UD, listen_id_priv);
	if (IS_ERR(id_priv)) return NULL;

	id = &id_priv->id;
	// 保存网络信息
	if (cma_save_net_info((struct sockaddr *)&id->route.addr.src_addr,
			      (struct sockaddr *)&id->route.addr.dst_addr,
			      listen_id, ib_event, ss_family,
			      ib_event->param.sidr_req_rcvd.service_id))
		goto err;

	if (net_dev) {
		// 从net_dev复制源L2地址
		rdma_copy_src_l2_addr(&id->route.addr.dev_addr, net_dev);
	} else {
		if (!cma_any_addr(cma_src_addr(id_priv))) {
			// 没有net_dev，尝试从src_addr翻译L2地址
			ret = cma_translate_addr(cma_src_addr(id_priv), &id->route.addr.dev_addr);
			if (ret) goto err;
		}
	}
	// 设置状态为连接
	id_priv->state = RDMA_CM_CONNECT;
	return id_priv;
err:
	rdma_destroy_id(id);
	return NULL;
}
```

##### 5. 服务端响应连接请求

服务端在接收连接请求后，需要响应客户端的连接请求，设置的`.cm_handler`为`cma_ib_handler`，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_ib_handler(struct ib_cm_id *cm_id, const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	struct rdma_cm_event event = {};
	enum rdma_cm_state state;
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	state = READ_ONCE(id_priv->state);
	// 检查事件是否匹配当前状态
	if ((ib_event->event != IB_CM_TIMEWAIT_EXIT && state != RDMA_CM_CONNECT) ||
	    (ib_event->event == IB_CM_TIMEWAIT_EXIT && state != RDMA_CM_DISCONNECT))
		goto out;

	switch (ib_event->event) {
		...
	case IB_CM_REP_RECEIVED:
		if (state == RDMA_CM_CONNECT && (id_priv->id.qp_type != IB_QPT_UD)) {
			// 检查是否为RC/UC连接，需要准备MRA
			trace_cm_prepare_mra(id_priv);
			ib_prepare_cm_mra(cm_id);
		}
		if (id_priv->id.qp) {
			// 设置qp时，发送应答连接请求
			event.status = cma_rep_recv(id_priv);
			event.event = event.status ? RDMA_CM_EVENT_CONNECT_ERROR : RDMA_CM_EVENT_ESTABLISHED;
		} else {
			// 没有qp时，发送连接响应
			event.event = RDMA_CM_EVENT_CONNECT_RESPONSE;
		}
		// 设置连接响应数据
		cma_set_rep_event_data(&event, &ib_event->param.rep_rcvd, ib_event->private_data);
		break;
		...
	}
	// 向用户空间发送事件
	ret = cma_cm_event_handler(id_priv, &event);
	if (ret) { ... }
out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}
```

在cm id关联的qp上发送连接响应后，建立连接，状态变更为`RDMA_CM_ESTABLISHED`，否则状态变更为`RDMA_CM_EVENT_CONNECT_RESPONSE`，此时服务端可以通过`rdma_get_request`获取连接请求。

##### 6. 服务端接收连接请求

服务端通过`rdma_accept`接收客户端的连接，通过`cma_send_sidr_rep`发送连接响应。如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_send_sidr_rep(struct rdma_id_private *id_priv,
			     enum ib_cm_sidr_status status, u32 qkey,
			     const void *private_data, int private_data_len)
{
	struct ib_cm_sidr_rep_param rep;
	int ret;

	memset(&rep, 0, sizeof rep);
	rep.status = status;
	if (status == IB_SIDR_SUCCESS) {
		// 设置qkey
		if (qkey) ret = cma_set_qkey(id_priv, qkey);
		else ret = cma_set_default_qkey(id_priv);
		if (ret) return ret;
		// 设置qp num和qkey
		rep.qp_num = id_priv->qp_num;
		rep.qkey = id_priv->qkey;

		rep.ece.vendor_id = id_priv->ece.vendor_id;
		rep.ece.attr_mod = id_priv->ece.attr_mod;
	}
	rep.private_data = private_data;
	rep.private_data_len = private_data_len;

	trace_cm_send_sidr_rep(id_priv);
	return ib_send_cm_sidr_rep(id_priv->cm_id.ib, &rep);
}
```

##### 7. 客户端响应SIDR请求

客户端设置的`.cm_handler`为`cma_sidr_rep_handler`，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_sidr_rep_handler(struct ib_cm_id *cm_id, const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	struct rdma_cm_event event = {};
	const struct ib_cm_sidr_rep_event_param *rep = &ib_event->param.sidr_rep_rcvd;
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	if (READ_ONCE(id_priv->state) != RDMA_CM_CONNECT)
		goto out;

	switch (ib_event->event) {
	case IB_CM_SIDR_REQ_ERROR:
		// 处理SIDR请求错误
		event.event = RDMA_CM_EVENT_UNREACHABLE;
		event.status = -ETIMEDOUT;
		break;
	case IB_CM_SIDR_REP_RECEIVED:
		event.param.ud.private_data = ib_event->private_data;
		event.param.ud.private_data_len = IB_CM_SIDR_REP_PRIVATE_DATA_SIZE;
		if (rep->status != IB_SIDR_SUCCESS) {
			event.event = RDMA_CM_EVENT_UNREACHABLE;
			event.status = ib_event->param.sidr_rep_rcvd.status;
			pr_debug_ratelimited("RDMA CM: UNREACHABLE: bad SIDR reply. status %d\n", event.status);
			break;
		}
		// 设置qkey
		ret = cma_set_qkey(id_priv, rep->qkey);
		if (ret) { ... }
		// 初始化AH属性
		ib_init_ah_attr_from_path(id_priv->id.device, id_priv->id.port_num, id_priv->id.route.path_rec,
					  &event.param.ud.ah_attr, rep->sgid_attr);
		event.param.ud.qp_num = rep->qpn;
		event.param.ud.qkey = rep->qkey;
		// 设置事件为ESTABLISHED
		event.event = RDMA_CM_EVENT_ESTABLISHED;
		event.status = 0;
		break;
	default:
		pr_err("RDMA CMA: unexpected IB CM event: %d\n", ib_event->event);
		goto out;
	}
	// 向用户空间发送事件
	ret = cma_cm_event_handler(id_priv, &event);
	// 销毁AH属性
	rdma_destroy_ah_attr(&event.param.ud.ah_attr);
	if (ret) { ... }
out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}
```

#### 3.19.6 通过RC/UC建立连接的处理过程

通过`RC/UC`连接的过程和`UD`连接的过程类似，实现的主要区别在：

##### 1. 服务端监听

和UD连接的过程相同。

##### 2. 客户端建立RC/UC连接

客户端通过`rdma_connect`建立连接，通过`cma_connect_ib`建立RC/UC连接，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_connect_ib(struct rdma_id_private *id_priv, struct rdma_conn_param *conn_param)
{
	struct ib_cm_req_param req;
	struct rdma_route *route;
	void *private_data;
	struct ib_cm_id	*id;
	u8 offset;
	int ret;

	memset(&req, 0, sizeof req);
	offset = cma_user_data_offset(id_priv);
	if (check_add_overflow(offset, conn_param->private_data_len, &req.private_data_len))
		return -EINVAL;
	// 设置私有数据
	if (req.private_data_len) {
		private_data = kzalloc(req.private_data_len, GFP_ATOMIC);
		if (!private_data) return -ENOMEM;
	} else {
		private_data = NULL;
	}
	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(private_data + offset, conn_param->private_data, conn_param->private_data_len);
	
	// 创建CM ID
	id = ib_create_cm_id(id_priv->id.device, cma_ib_handler, id_priv);
	if (IS_ERR(id)) { ... }
	id_priv->cm_id.ib = id;

	route = &id_priv->id.route;
	if (private_data) {
		// 设置cmd同步信息
		ret = cma_format_hdr(private_data, id_priv);
		if (ret) goto out;
		req.private_data = private_data;
	}
	// 设置请求参数
	req.primary_path = &route->path_rec[0];
	req.primary_path_inbound = route->path_rec_inbound;
	req.primary_path_outbound = route->path_rec_outbound;
	if (route->num_pri_alt_paths == 2)
		req.alternate_path = &route->path_rec[1];

	req.ppath_sgid_attr = id_priv->id.route.addr.dev_addr.sgid_attr;
	// 设置服务ID
	req.service_id = rdma_get_service_id(&id_priv->id, cma_dst_addr(id_priv));
	// 设置qp相关参数
	req.qp_num = id_priv->qp_num;
	req.qp_type = id_priv->id.qp_type;
	req.starting_psn = id_priv->seq_num;
	req.responder_resources = conn_param->responder_resources;
	req.initiator_depth = conn_param->initiator_depth;
	req.flow_control = conn_param->flow_control;
	req.retry_count = min_t(u8, 7, conn_param->retry_count);
	req.rnr_retry_count = min_t(u8, 7, conn_param->rnr_retry_count);
	req.remote_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.local_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.max_cm_retries = CMA_MAX_CM_RETRIES;
	req.srq = id_priv->srq ? 1 : 0;
	req.ece.vendor_id = id_priv->ece.vendor_id;
	req.ece.attr_mod = id_priv->ece.attr_mod;

	trace_cm_send_req(id_priv);
	// 发送CM请求
	ret = ib_send_cm_req(id_priv->cm_id.ib, &req);
out:
	if (ret && !IS_ERR(id)) {
		ib_destroy_cm_id(id);
		id_priv->cm_id.ib = NULL;
	}
	kfree(private_data);
	return ret;
}
```

##### 3. 服务端处理连接请求

客户端发送`cm_req`请求，设置的标记为`CM_REQ_ATTR_ID`, 对应`IB_CM_REQ_RECEIVED`状态，服务端在接收该请求后，对应`cm_req_handler`处理，如下：

```c
// file: drivers/infiniband/core/cm.c
static int cm_req_handler(struct cm_work *work)
{
	struct cm_id_private *cm_id_priv, *listen_cm_id_priv;
	struct cm_req_msg *req_msg;
	const struct ib_global_route *grh;
	const struct ib_gid_attr *gid_attr;
	int ret;

	req_msg = (struct cm_req_msg *)work->mad_recv_wc->recv_buf.mad;
	// 分配CM ID
	cm_id_priv = cm_alloc_id_priv(work->port->cm_dev->ib_device, NULL, NULL);
	if (IS_ERR(cm_id_priv)) return PTR_ERR(cm_id_priv);
	// 设置CM ID属性
	cm_id_priv->id.remote_id = cpu_to_be32(IBA_GET(CM_REQ_LOCAL_COMM_ID, req_msg));
	cm_id_priv->id.service_id = cpu_to_be64(IBA_GET(CM_REQ_SERVICE_ID, req_msg));
	cm_id_priv->tid = req_msg->hdr.tid;
	cm_id_priv->timeout_ms = cm_convert_to_ms( IBA_GET(CM_REQ_LOCAL_CM_RESPONSE_TIMEOUT, req_msg));
	cm_id_priv->max_cm_retries = IBA_GET(CM_REQ_MAX_CM_RETRIES, req_msg);
	cm_id_priv->remote_qpn = cpu_to_be32(IBA_GET(CM_REQ_LOCAL_QPN, req_msg));
	cm_id_priv->initiator_depth = IBA_GET(CM_REQ_RESPONDER_RESOURCES, req_msg);
	cm_id_priv->responder_resources = IBA_GET(CM_REQ_INITIATOR_DEPTH, req_msg);
	cm_id_priv->path_mtu = IBA_GET(CM_REQ_PATH_PACKET_PAYLOAD_MTU, req_msg);
	cm_id_priv->pkey = cpu_to_be16(IBA_GET(CM_REQ_PARTITION_KEY, req_msg));
	cm_id_priv->sq_psn = cpu_to_be32(IBA_GET(CM_REQ_STARTING_PSN, req_msg));
	cm_id_priv->retry_count = IBA_GET(CM_REQ_RETRY_COUNT, req_msg);
	cm_id_priv->rnr_retry_count = IBA_GET(CM_REQ_RNR_RETRY_COUNT, req_msg);
	cm_id_priv->qp_type = cm_req_get_qp_type(req_msg);
	// 初始化`av`，用于响应请求
	ret = cm_init_av_for_response(work->port, work->mad_recv_wc->wc,
				      work->mad_recv_wc->recv_buf.grh, &cm_id_priv->av);
	if (ret) goto destroy;
	cm_id_priv->timewait_info = cm_create_timewait_info(cm_id_priv-> id.local_id);
	if (IS_ERR(cm_id_priv->timewait_info)) { ... }
	cm_id_priv->timewait_info->work.remote_id = cm_id_priv->id.remote_id;
	cm_id_priv->timewait_info->remote_ca_guid = cpu_to_be64(IBA_GET(CM_REQ_LOCAL_CA_GUID, req_msg));
	cm_id_priv->timewait_info->remote_qpn = cm_id_priv->remote_qpn;
	// 设置CM ID状态为RCVD
	cm_id_priv->id.state = IB_CM_REQ_RCVD;

	// 获取监听的CM ID
	listen_cm_id_priv = cm_match_req(work, cm_id_priv);
	if (!listen_cm_id_priv) { ... }

	memset(&work->path[0], 0, sizeof(work->path[0]));
	if (cm_req_has_alt_path(req_msg))
		memset(&work->path[1], 0, sizeof(work->path[1]));
	grh = rdma_ah_read_grh(&cm_id_priv->av.ah_attr);
	gid_attr = grh->sgid_attr;

	if (cm_id_priv->av.ah_attr.type == RDMA_AH_ATTR_TYPE_ROCE) {
		work->path[0].rec_type = sa_conv_gid_to_pathrec_type(gid_attr->gid_type);
	} else {
		cm_process_routed_req(req_msg, work->mad_recv_wc->wc);
		cm_path_set_rec_type(work->port->cm_dev->ib_device, work->port->port_num,
			&work->path[0], IBA_GET_MEM_PTR(CM_REQ_PRIMARY_LOCAL_PORT_GID, req_msg));
	}
	if (cm_req_has_alt_path(req_msg))
		work->path[1].rec_type = work->path[0].rec_type;
	cm_format_paths_from_req(req_msg, &work->path[0], &work->path[1], work->mad_recv_wc->wc);
	if (cm_id_priv->av.ah_attr.type == RDMA_AH_ATTR_TYPE_ROCE)
		sa_path_set_dmac(&work->path[0], cm_id_priv->av.ah_attr.roce.dmac);
	work->path[0].hop_limit = grh->hop_limit;

	cm_destroy_av(&cm_id_priv->av);
	ret = cm_init_av_by_path(&work->path[0], gid_attr, &cm_id_priv->av);
	if (ret) {
		// 失败时发送CM拒绝响应
		int err;
		err = rdma_query_gid(work->port->cm_dev->ib_device, work->port->port_num, 0,
				     &work->path[0].sgid);
		if (err) ib_send_cm_rej(&cm_id_priv->id, IB_CM_REJ_INVALID_GID, NULL, 0, NULL, 0);
		else ib_send_cm_rej(&cm_id_priv->id, IB_CM_REJ_INVALID_GID, &work->path[0].sgid,
				       sizeof(work->path[0].sgid), NULL, 0);
		goto rejected;
	}
	if (cm_id_priv->av.ah_attr.type == RDMA_AH_ATTR_TYPE_IB)
		cm_id_priv->av.dlid_datapath = IBA_GET(CM_REQ_PRIMARY_LOCAL_PORT_LID, req_msg);

	if (cm_req_has_alt_path(req_msg)) {
		ret = cm_init_av_by_path(&work->path[1], NULL, &cm_id_priv->alt_av);
		if (ret) {
			ib_send_cm_rej(&cm_id_priv->id, IB_CM_REJ_INVALID_ALT_GID,
				       &work->path[0].sgid, sizeof(work->path[0].sgid), NULL, 0);
			goto rejected;
		}
	}
	// 设置CM ID处理函数
	cm_id_priv->id.cm_handler = listen_cm_id_priv->id.cm_handler;
	cm_id_priv->id.context = listen_cm_id_priv->id.context;
	cm_format_req_event(work, cm_id_priv, &listen_cm_id_priv->id);

	spin_lock_irq(&cm_id_priv->lock);
	cm_finalize_id(cm_id_priv);

	refcount_inc(&cm_id_priv->refcount);
	// 加入工作队列
	cm_queue_work_unlock(cm_id_priv, work);
	cm_deref_id(listen_cm_id_priv);
	return 0;
rejected:
	cm_deref_id(listen_cm_id_priv);
destroy:
	ib_destroy_cm_id(&cm_id_priv->id);
	return ret;
}
```

可以看到，在创建新的cm id后，设置了`cm_id_priv->id.cm_handler`为监听cm id的`cm_handler`，设置为`cma_ib_req_handler`，实现同UD方式相同。

##### 4. 创建RC/UC连接

服务端处理连接请求时，通过`cma_ib_new_conn_id`创建新的cm id，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static struct rdma_id_private * cma_ib_new_conn_id(const struct rdma_cm_id *listen_id,
		   const struct ib_cm_event *ib_event, struct net_device *net_dev)
{
	struct rdma_id_private *listen_id_priv;
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	struct rdma_route *rt;
	const sa_family_t ss_family = listen_id->route.addr.src_addr.ss_family;
	struct sa_path_rec *path = ib_event->param.req_rcvd.primary_path;
	const __be64 service_id = ib_event->param.req_rcvd.primary_path->service_id;
	int ret;

	listen_id_priv = container_of(listen_id, struct rdma_id_private, id);
	// 创建新的CM ID
	id_priv = __rdma_create_id(listen_id->route.addr.dev_addr.net,
				   listen_id->event_handler, listen_id->context,
				   listen_id->ps, ib_event->param.req_rcvd.qp_type, listen_id_priv);
	if (IS_ERR(id_priv)) return NULL;

	id = &id_priv->id;
	// 保存网络信息
	if (cma_save_net_info((struct sockaddr *)&id->route.addr.src_addr,
			      (struct sockaddr *)&id->route.addr.dst_addr,
			      listen_id, ib_event, ss_family, service_id))
		goto err;

	rt = &id->route;
	rt->num_pri_alt_paths = ib_event->param.req_rcvd.alternate_path ? 2 : 1;
	rt->path_rec = kmalloc_objs(*rt->path_rec, rt->num_pri_alt_paths);
	if (!rt->path_rec) goto err;

	rt->path_rec[0] = *path;
	if (rt->num_pri_alt_paths == 2)
		rt->path_rec[1] = *ib_event->param.req_rcvd.alternate_path;

	if (net_dev) {
		// 复制源L2地址
		rdma_copy_src_l2_addr(&rt->addr.dev_addr, net_dev);
	} else {
		if (!cma_protocol_roce(listen_id) && cma_any_addr(cma_src_addr(id_priv))) {
			// 设置设备类型为INFINIBAND
			rt->addr.dev_addr.dev_type = ARPHRD_INFINIBAND;
			rdma_addr_set_sgid(&rt->addr.dev_addr, &rt->path_rec[0].sgid);
			ib_addr_set_pkey(&rt->addr.dev_addr, be16_to_cpu(rt->path_rec[0].pkey));
		} else if (!cma_any_addr(cma_src_addr(id_priv))) {
			// 转换源地址
			ret = cma_translate_addr(cma_src_addr(id_priv), &rt->addr.dev_addr);
			if (ret) goto err;
		}
	}
	// 设置dgid
	rdma_addr_set_dgid(&rt->addr.dev_addr, &rt->path_rec[0].dgid);
	// 设置状态为连接状态
	id_priv->state = RDMA_CM_CONNECT;
	return id_priv;
err:
	rdma_destroy_id(id);
	return NULL;
}
```

##### 5. 服务端响应连接请求

和UD连接的过程相同。不同之处在于，服务端需要准备MRA，通过`ib_prepare_cm_mra`实现。

##### 6. 服务端接收连接请求

服务端通过`rdma_accept`接收客户端的连接，通过`cma_accept_ib`或者`cma_rep_recv`发送连接响应。如下：

* 发送连接响应

`cma_accept_ib`接收IB设备的连接请求，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_accept_ib(struct rdma_id_private *id_priv, struct rdma_conn_param *conn_param)
{
	struct ib_cm_rep_param rep;
	int ret;
	// 修改QP为RTR状态
	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret) goto out;
	// 修改QP为RTS状态
	ret = cma_modify_qp_rts(id_priv, conn_param);
	if (ret) goto out;

	// 设置连接响应参数
	memset(&rep, 0, sizeof rep);
	rep.qp_num = id_priv->qp_num;
	rep.starting_psn = id_priv->seq_num;
	rep.private_data = conn_param->private_data;
	rep.private_data_len = conn_param->private_data_len;
	rep.responder_resources = conn_param->responder_resources;
	rep.initiator_depth = conn_param->initiator_depth;
	rep.failover_accepted = 0;
	rep.flow_control = conn_param->flow_control;
	rep.rnr_retry_count = min_t(u8, 7, conn_param->rnr_retry_count);
	rep.srq = id_priv->srq ? 1 : 0;
	rep.ece.vendor_id = id_priv->ece.vendor_id;
	rep.ece.attr_mod = id_priv->ece.attr_mod;

	trace_cm_send_rep(id_priv);
	// 发送cm连接响应
	ret = ib_send_cm_rep(id_priv->cm_id.ib, &rep);
out:
	return ret;
}
```

`cm_rep`通过MRA发送连接响应，这里不进行详细分析。

* 发送RTU

`cma_rep_recv`发送连接响应后，建立连接，状态变更为`RDMA_CM_ESTABLISHED`。

```c
// file: drivers/infiniband/core/cma.c
static int cma_rep_recv(struct rdma_id_private *id_priv)
{
	int ret;
	// 修改QP为RTR状态
	ret = cma_modify_qp_rtr(id_priv, NULL);
	if (ret) goto reject;
	// 修改QP为RTS状态
	ret = cma_modify_qp_rts(id_priv, NULL);
	if (ret) goto reject;

	trace_cm_send_rtu(id_priv);
	// 发送RTU
	ret = ib_send_cm_rtu(id_priv->cm_id.ib, NULL, 0);
	if (ret) goto reject;
	return 0;
reject:
	pr_debug_ratelimited("RDMA CM: CONNECT_ERROR: failed to handle reply. status %d\n", ret);
	cma_modify_qp_err(id_priv);
	trace_cm_send_rej(id_priv);
	// 失败发送拒绝请求
	ib_send_cm_rej(id_priv->cm_id.ib, IB_CM_REJ_CONSUMER_DEFINED, NULL, 0, NULL, 0);
	return ret;
}
```

`ib_send_cm_rtu`函数发送RTU消息，用于响应连接请求，建立连接。。如下：

```c
// file: drivers/infiniband/core/cm.c
int ib_send_cm_rtu(struct ib_cm_id *cm_id, const void *private_data, u8 private_data_len)
{
	struct cm_id_private *cm_id_priv;
	struct ib_mad_send_buf *msg;
	unsigned long flags;
	void *data;
	int ret;

	if (private_data && private_data_len > IB_CM_RTU_PRIVATE_DATA_SIZE)
		return -EINVAL;
	// 复制私有数据
	data = cm_copy_private_data(private_data, private_data_len);
	if (IS_ERR(data)) return PTR_ERR(data);

	cm_id_priv = container_of(cm_id, struct cm_id_private, id);
	spin_lock_irqsave(&cm_id_priv->lock, flags);
	if (cm_id->state != IB_CM_REP_RCVD && cm_id->state != IB_CM_MRA_REP_SENT) { ... }

	// 分配消息缓冲区
	msg = cm_alloc_msg(cm_id_priv);
	if (IS_ERR(msg)) { ... }

	// 格式化RTU消息
	cm_format_rtu((struct cm_rtu_msg *) msg->mad, cm_id_priv, private_data, private_data_len);
	trace_icm_send_rtu(cm_id);
	// 发送RTU消息
	ret = ib_post_send_mad(msg, NULL);
	if (ret) { ... }

	// 更新状态为已建立
	cm_id->state = IB_CM_ESTABLISHED;
	cm_set_private_data(cm_id_priv, data, private_data_len);
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	return 0;
error:	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	kfree(data);
	return ret;
}
```

##### 7. 客户端响应请求

客户端设置的`.cm_handler`为`cma_ib_handler`，实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_ib_handler(struct ib_cm_id *cm_id, const struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	struct rdma_cm_event event = {};
	enum rdma_cm_state state;
	int ret;

	mutex_lock(&id_priv->handler_mutex);
	state = READ_ONCE(id_priv->state);
	// 检查事件是否匹配当前状态
	if ((ib_event->event != IB_CM_TIMEWAIT_EXIT && state != RDMA_CM_CONNECT) ||
	    (ib_event->event == IB_CM_TIMEWAIT_EXIT && state != RDMA_CM_DISCONNECT))
		goto out;

	switch (ib_event->event) {
		...
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		// 客户端建立连接
		event.event = RDMA_CM_EVENT_ESTABLISHED;
		break;
		...
	}
	// 向用户空间发送事件
	ret = cma_cm_event_handler(id_priv, &event);
	if (ret) { ... }
out:
	mutex_unlock(&id_priv->handler_mutex);
	return 0;
}
```

#### 3.19.7 通过iWARP建立连接的处理过程

##### 1. 服务端监听

在CM ID关联iWARP设备时，通过`cma_iw_listen`进行监听。实现如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_iw_listen(struct rdma_id_private *id_priv, int backlog)
{
	int ret;
	struct iw_cm_id	*id;
	// 创建新的cm id
	id = iw_create_cm_id(id_priv->id.device, iw_conn_req_handler, id_priv);
	if (IS_ERR(id)) return PTR_ERR(id);

	mutex_lock(&id_priv->qp_mutex);
	// 设置相关参数
	id->tos = id_priv->tos;
	id->tos_set = id_priv->tos_set;
	mutex_unlock(&id_priv->qp_mutex);
	id->afonly = id_priv->afonly;
	id_priv->cm_id.iw = id;

	// 复制本地地址
	memcpy(&id_priv->cm_id.iw->local_addr, cma_src_addr(id_priv),
	       rdma_addr_size(cma_src_addr(id_priv)));
	// 进行监听
	ret = iw_cm_listen(id_priv->cm_id.iw, backlog);
	if (ret) {
		iw_destroy_cm_id(id_priv->cm_id.iw);
		id_priv->cm_id.iw = NULL;
	}
	return ret;
}
```

`iw_create_cm_id`创建新的iWARP CM ID，如下：

```c
// file: drivers/infiniband/core/iwcm.c
struct iw_cm_id *iw_create_cm_id(struct ib_device *device, iw_cm_handler cm_handler, void *context)
{
	struct iwcm_id_private *cm_id_priv;
	// 分配cm id
	cm_id_priv = kzalloc(sizeof(*cm_id_priv), GFP_KERNEL);
	if (!cm_id_priv) return ERR_PTR(-ENOMEM);
	// 设置相关参数
	cm_id_priv->state = IW_CM_STATE_IDLE;
	cm_id_priv->id.device = device;
	cm_id_priv->id.cm_handler = cm_handler;
	cm_id_priv->id.context = context;
	cm_id_priv->id.event_handler = cm_event_handler;
	cm_id_priv->id.add_ref = add_ref;
	cm_id_priv->id.rem_ref = rem_ref;
	spin_lock_init(&cm_id_priv->lock);
	refcount_set(&cm_id_priv->refcount, 1);
	init_waitqueue_head(&cm_id_priv->connect_wait);
	init_completion(&cm_id_priv->destroy_comp);
	INIT_LIST_HEAD(&cm_id_priv->work_list);
	INIT_LIST_HEAD(&cm_id_priv->work_free_list);
	return &cm_id_priv->id;
}
```

`iw_cm_listen`进行监听操作，如下：

```c
// file: drivers/infiniband/core/iwcm.c
int iw_cm_listen(struct iw_cm_id *cm_id, int backlog)
{
	struct iwcm_id_private *cm_id_priv;
	unsigned long flags;
	int ret;

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	// backlog检查，默认256
	if (!backlog) backlog = default_backlog;
	// 分配`iwcm_work`
	ret = alloc_work_entries(cm_id_priv, backlog);
	if (ret) return ret;

	spin_lock_irqsave(&cm_id_priv->lock, flags);
	switch (cm_id_priv->state) {
	case IW_CM_STATE_IDLE:
		cm_id_priv->state = IW_CM_STATE_LISTEN;
		spin_unlock_irqrestore(&cm_id_priv->lock, flags);
		// 映射iwarp
		ret = iw_cm_map(cm_id, false);
		if (!ret)
			// 调用`.iw_create_listen`接口进行监听
			ret = cm_id->device->ops.iw_create_listen(cm_id, backlog);
		if (ret) cm_id_priv->state = IW_CM_STATE_IDLE;
		spin_lock_irqsave(&cm_id_priv->lock, flags);
		break;
	default:
		ret = -EINVAL;
	}
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	return ret;
}
```

##### 2. 客户端建立连接

客户端通过`rdma_connect`建立连接，通过`cma_connect_iw`建立iWARP连接，如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_connect_iw(struct rdma_id_private *id_priv, struct rdma_conn_param *conn_param)
{
	struct iw_cm_id *cm_id;
	int ret;
	struct iw_cm_conn_param iw_param;
	// 创建CM ID
	cm_id = iw_create_cm_id(id_priv->id.device, cma_iw_handler, id_priv);
	if (IS_ERR(cm_id)) return PTR_ERR(cm_id);

	mutex_lock(&id_priv->qp_mutex);
	cm_id->tos = id_priv->tos;
	cm_id->tos_set = id_priv->tos_set;
	mutex_unlock(&id_priv->qp_mutex);

	id_priv->cm_id.iw = cm_id;

	memcpy(&cm_id->local_addr, cma_src_addr(id_priv), rdma_addr_size(cma_src_addr(id_priv)));
	memcpy(&cm_id->remote_addr, cma_dst_addr(id_priv), rdma_addr_size(cma_dst_addr(id_priv)));
	// 修改qp属性，设置为RTR状态
	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret) goto out;

	if (conn_param) {
		iw_param.ord = conn_param->initiator_depth;
		iw_param.ird = conn_param->responder_resources;
		iw_param.private_data = conn_param->private_data;
		iw_param.private_data_len = conn_param->private_data_len;
		iw_param.qpn = id_priv->id.qp ? id_priv->qp_num : conn_param->qp_num;
	} else {
		memset(&iw_param, 0, sizeof iw_param);
		iw_param.qpn = id_priv->qp_num;
	}
	// 执行连接操作
	ret = iw_cm_connect(cm_id, &iw_param);
out:
	if (ret) {
		iw_destroy_cm_id(cm_id);
		id_priv->cm_id.iw = NULL;
	}
	return ret;
}
```

`iw_cm_connect`在获取qp后，映射iWARP端口后，执行`.iw_connect`操作，如下：

```c
// file: drivers/infiniband/core/iwcm.c
int iw_cm_connect(struct iw_cm_id *cm_id, struct iw_cm_conn_param *iw_param)
{
	struct iwcm_id_private *cm_id_priv;
	int ret;
	unsigned long flags;
	struct ib_qp *qp = NULL;

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	// 创建work
	ret = alloc_work_entries(cm_id_priv, 4);
	if (ret) return ret;

	set_bit(IWCM_F_CONNECT_WAIT, &cm_id_priv->flags);
	spin_lock_irqsave(&cm_id_priv->lock, flags);
	// 检查状态
	if (cm_id_priv->state != IW_CM_STATE_IDLE) { ... }

	// 获取qp
	qp = cm_id->device->ops.iw_get_qp(cm_id->device, iw_param->qpn);
	if (!qp) { ... }
	cm_id->device->ops.iw_add_ref(qp);
	cm_id_priv->qp = qp;
	cm_id_priv->state = IW_CM_STATE_CONN_SENT;
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	// 映射cm id
	ret = iw_cm_map(cm_id, true);
	// 调用`.iw_connect`接口
	if (!ret) ret = cm_id->device->ops.iw_connect(cm_id, iw_param);
	if (!ret) return 0;	/* success */

	// 失败时的清理工作
	spin_lock_irqsave(&cm_id_priv->lock, flags);
	qp = cm_id_priv->qp;
	cm_id_priv->qp = NULL;
	cm_id_priv->state = IW_CM_STATE_IDLE;
err:
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	if (qp) cm_id->device->ops.iw_rem_ref(qp);
	clear_bit(IWCM_F_CONNECT_WAIT, &cm_id_priv->flags);
	wake_up_all(&cm_id_priv->connect_wait);
	return ret;
}
```

##### 3. iWARP连接事件处理过程

iWARP设置的`.event_handler`为`cm_event_handler`，如下：

```c
// file: drivers/infiniband/core/iwcm.c
static int cm_event_handler(struct iw_cm_id *cm_id, struct iw_cm_event *iw_event)
{
	struct iwcm_work *work;
	struct iwcm_id_private *cm_id_priv;
	unsigned long flags;
	int ret = 0;

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	spin_lock_irqsave(&cm_id_priv->lock, flags);
	work = get_work(cm_id_priv);
	if (!work) { ... }

	// 初始化work
	INIT_WORK(&work->work, cm_work_handler);
	work->cm_id = cm_id_priv;
	work->event = *iw_event;

	if ((work->event.event == IW_CM_EVENT_CONNECT_REQUEST ||
	     work->event.event == IW_CM_EVENT_CONNECT_REPLY) &&
	    work->event.private_data_len) {
		ret = copy_private_data(&work->event);
		if (ret) { ... }
	}

	refcount_inc(&cm_id_priv->refcount);
	queue_work(iwcm_wq, &work->work);
out:
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	return ret;
}
```

`work`设置执行函数为`cm_work_handler`，实现如下：

```c
// file: drivers/infiniband/core/iwcm.c
static void cm_work_handler(struct work_struct *_work)
{
	struct iwcm_work *work = container_of(_work, struct iwcm_work, work);
	struct iw_cm_event levent;
	struct iwcm_id_private *cm_id_priv = work->cm_id;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&cm_id_priv->lock, flags);
	levent = work->event;
	put_work(work);
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);

	if (!test_bit(IWCM_F_DROP_EVENTS, &cm_id_priv->flags)) {
		ret = process_event(cm_id_priv, &levent);
		if (ret) { ... }
	} else
		pr_debug("dropping event %d\n", levent.event);
	if (iwcm_deref_id(cm_id_priv))
		return;
}
```

`process_event`函数处理事件，如下：

```c
// file: drivers/infiniband/core/iwcm.c
static int process_event(struct iwcm_id_private *cm_id_priv,
			 struct iw_cm_event *iw_event)
{
	int ret = 0;

	switch (iw_event->event) {
	case IW_CM_EVENT_CONNECT_REQUEST:
		cm_conn_req_handler(cm_id_priv, iw_event);
		break;
	case IW_CM_EVENT_CONNECT_REPLY:
		ret = cm_conn_rep_handler(cm_id_priv, iw_event);
		break;
	case IW_CM_EVENT_ESTABLISHED:
		ret = cm_conn_est_handler(cm_id_priv, iw_event);
		break;
	case IW_CM_EVENT_DISCONNECT:
		cm_disconnect_handler(cm_id_priv, iw_event);
		break;
	case IW_CM_EVENT_CLOSE:
		ret = cm_close_handler(cm_id_priv, iw_event);
		break;
	default:
		BUG();
	}
	return ret;
}
```

##### 4. 服务端处理连接请求

服务端接收客户端发送的`CONNECT_REQUEST`，对应的处理函数为`cm_conn_req_handler`，实现如下：

```c
// file: drivers/infiniband/core/iwcm.c
static void cm_conn_req_handler(struct iwcm_id_private *listen_id_priv,
				struct iw_cm_event *iw_event)
{
	unsigned long flags;
	struct iw_cm_id *cm_id;
	struct iwcm_id_private *cm_id_priv;
	int ret;

	BUG_ON(iw_event->status);
	// 创建cm id
	cm_id = iw_create_cm_id(listen_id_priv->id.device,
				listen_id_priv->id.cm_handler,
				listen_id_priv->id.context);
	if (IS_ERR(cm_id)) goto out;

	cm_id->provider_data = iw_event->provider_data;
	cm_id->m_local_addr = iw_event->local_addr;
	cm_id->m_remote_addr = iw_event->remote_addr;
	cm_id->local_addr = listen_id_priv->id.local_addr;
	// 获取远程地址
	ret = iwpm_get_remote_info(&listen_id_priv->id.m_local_addr, &iw_event->remote_addr,
				   &cm_id->remote_addr, RDMA_NL_IWCM);
	if (ret) {
		cm_id->remote_addr = iw_event->remote_addr;
	} else {
		iw_cm_check_wildcard(&listen_id_priv->id.m_local_addr,
				     &iw_event->local_addr, &cm_id->local_addr);
		iw_event->local_addr = cm_id->local_addr;
		iw_event->remote_addr = cm_id->remote_addr;
	}

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	cm_id_priv->state = IW_CM_STATE_CONN_RECV;

	spin_lock_irqsave(&listen_id_priv->lock, flags);
	if (listen_id_priv->state != IW_CM_STATE_LISTEN) {
		// 监听状态错误，拒绝连接
		spin_unlock_irqrestore(&listen_id_priv->lock, flags);
		iw_cm_reject(cm_id, NULL, 0);
		iw_destroy_cm_id(cm_id);
		goto out;
	}
	spin_unlock_irqrestore(&listen_id_priv->lock, flags);

	ret = alloc_work_entries(cm_id_priv, 3);
	if (ret) { ... }

	// 调用客户CM处理函数
	ret = cm_id->cm_handler(cm_id, iw_event);
	if (ret) {
		iw_cm_reject(cm_id, NULL, 0);
		iw_destroy_cm_id(cm_id);
	}
out:
	if (iw_event->private_data_len)
		kfree(iw_event->private_data);
}
```

##### 5. 服务端响应连接请求

服务端在创建连接请求后，通过`iw_conn_req_handler`处理，如下：

```c
// file: drivers/infiniband/core/cma.c
static int iw_conn_req_handler(struct iw_cm_id *cm_id, struct iw_cm_event *iw_event)
{
	struct rdma_id_private *listen_id, *conn_id;
	struct rdma_cm_event event = {};
	int ret = -ECONNABORTED;
	struct sockaddr *laddr = (struct sockaddr *)&iw_event->local_addr;
	struct sockaddr *raddr = (struct sockaddr *)&iw_event->remote_addr;

	// `CONNECT_REQUEST`事件
	event.event = RDMA_CM_EVENT_CONNECT_REQUEST;
	event.param.conn.private_data = iw_event->private_data;
	event.param.conn.private_data_len = iw_event->private_data_len;
	event.param.conn.initiator_depth = iw_event->ird;
	event.param.conn.responder_resources = iw_event->ord;

	listen_id = cm_id->context;

	mutex_lock(&listen_id->handler_mutex);
	if (READ_ONCE(listen_id->state) != RDMA_CM_LISTEN)
		goto out;

	// 创建新的cm id
	conn_id = __rdma_create_id(listen_id->id.route.addr.dev_addr.net,
				   listen_id->id.event_handler,
				   listen_id->id.context, RDMA_PS_TCP,
				   IB_QPT_RC, listen_id);
	if (IS_ERR(conn_id)) { ... }
	mutex_lock_nested(&conn_id->handler_mutex, SINGLE_DEPTH_NESTING);
	conn_id->state = RDMA_CM_CONNECT;

	// 解析本地地址
	ret = rdma_translate_ip(laddr, &conn_id->id.route.addr.dev_addr);
	if (ret) { ... }

	ret = cma_iw_acquire_dev(conn_id, listen_id);
	if (ret) { ... }

	// 关联cm id
	conn_id->cm_id.iw = cm_id;
	cm_id->context = conn_id;
	// 设置cm handler
	cm_id->cm_handler = cma_iw_handler;

	memcpy(cma_src_addr(conn_id), laddr, rdma_addr_size(laddr));
	memcpy(cma_dst_addr(conn_id), raddr, rdma_addr_size(raddr));

	ret = cma_cm_event_handler(conn_id, &event);
	if (ret) { ... }
	mutex_unlock(&conn_id->handler_mutex);
out:
	mutex_unlock(&listen_id->handler_mutex);
	return ret;
}
```

##### 6. 服务端接收连接请求

服务端通过`rdma_accept`接收客户端的连接，通过`cma_accept_iw`发送连接响应。如下：

```c
// file: drivers/infiniband/core/cma.c
static int cma_accept_iw(struct rdma_id_private *id_priv, struct rdma_conn_param *conn_param)
{
	struct iw_cm_conn_param iw_param;
	int ret;
	// 检查参数
	if (!conn_param) return -EINVAL;
	// 修改qp为rtr状态
	ret = cma_modify_qp_rtr(id_priv, conn_param);
	if (ret) return ret;
	// 设置连接参数
	iw_param.ord = conn_param->initiator_depth;
	iw_param.ird = conn_param->responder_resources;
	iw_param.private_data = conn_param->private_data;
	iw_param.private_data_len = conn_param->private_data_len;
	if (id_priv->id.qp)
		iw_param.qpn = id_priv->qp_num;
	else
		iw_param.qpn = conn_param->qp_num;
	// 接收连接请求
	return iw_cm_accept(id_priv->cm_id.iw, &iw_param);
}
```

`iw_cm_accept`通过`.iw_accept`接口接收连接请求，如下：

```c
// file: drivers/infiniband/core/iwcm.c
int iw_cm_accept(struct iw_cm_id *cm_id, struct iw_cm_conn_param *iw_param)
{
	struct iwcm_id_private *cm_id_priv;
	struct ib_qp *qp;
	unsigned long flags;
	int ret;

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	set_bit(IWCM_F_CONNECT_WAIT, &cm_id_priv->flags);

	spin_lock_irqsave(&cm_id_priv->lock, flags);
	if (cm_id_priv->state != IW_CM_STATE_CONN_RECV) { ... }
	// 获取QP
	qp = cm_id->device->ops.iw_get_qp(cm_id->device, iw_param->qpn);
	if (!qp) { ... }
	cm_id->device->ops.iw_add_ref(qp);
	cm_id_priv->qp = qp;
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);
	// 调用`.iw_accept`接口
	ret = cm_id->device->ops.iw_accept(cm_id, iw_param);
	if (ret) { ... }
	return ret;
}
```

#### 3.19.8 CM断开连接的过程

##### 1. CM断开连接的过程

服务端和客户端通过`rdma_disconnect`断开连接，支持CM时，通过发送`dreq`和`drep`信息断开连接。

接收到`dreq`和`drep`后，对应的处理如下：

```c
static void cm_work_handler(struct work_struct *_work)
{
	struct cm_work *work = container_of(_work, struct cm_work, work.work);
	int ret;

	switch (work->cm_event.event) {
		...
	case IB_CM_DREQ_RECEIVED:
		ret = cm_dreq_handler(work);
		break;
	case IB_CM_DREP_RECEIVED:
		ret = cm_drep_handler(work);
		break;
		...	
	}
}
```

`cm_dreq_handler`处理`dreq`信息，如下：

```c
// file: drivers/infiniband/core/cm.c
static int cm_dreq_handler(struct cm_work *work)
{
	struct cm_id_private *cm_id_priv;
	struct cm_dreq_msg *dreq_msg;
	struct ib_mad_send_buf *msg = NULL;

	dreq_msg = (struct cm_dreq_msg *)work->mad_recv_wc->recv_buf.mad;
	// 查找cm id
	cm_id_priv = cm_acquire_id(
		cpu_to_be32(IBA_GET(CM_DREQ_REMOTE_COMM_ID, dreq_msg)),
		cpu_to_be32(IBA_GET(CM_DREQ_LOCAL_COMM_ID, dreq_msg)));
	if (!cm_id_priv) { ... }

	work->cm_event.private_data = IBA_GET_MEM_PTR(CM_DREQ_PRIVATE_DATA, dreq_msg);

	spin_lock_irq(&cm_id_priv->lock);
	if (cm_id_priv->local_qpn != cpu_to_be32(IBA_GET(CM_DREQ_REMOTE_QPN_EECN, dreq_msg)))
		goto unlock;

	switch (cm_id_priv->id.state) {
	case IB_CM_REP_SENT:
	case IB_CM_DREQ_SENT:
	case IB_CM_MRA_REP_RCVD:
		// 取消mad
		ib_cancel_mad(cm_id_priv->msg);
		break;
	case IB_CM_ESTABLISHED:
		if (cm_id_priv->id.lap_state == IB_CM_LAP_SENT ||
		    cm_id_priv->id.lap_state == IB_CM_MRA_LAP_RCVD)
			// 取消mad
			ib_cancel_mad(cm_id_priv->msg);
		break;
		...
	}
	cm_id_priv->id.state = IB_CM_DREQ_RCVD;
	cm_id_priv->tid = dreq_msg->hdr.tid;
	cm_queue_work_unlock(cm_id_priv, work);
	return 0;

unlock:	spin_unlock_irq(&cm_id_priv->lock);
deref:	cm_deref_id(cm_id_priv);
	return -EINVAL;
}
```

`cm_drep_handler`处理`drep`信息，如下：

```c
// file: drivers/infiniband/core/cm.c
static int cm_drep_handler(struct cm_work *work)
{
	struct cm_id_private *cm_id_priv;
	struct cm_drep_msg *drep_msg;

	drep_msg = (struct cm_drep_msg *)work->mad_recv_wc->recv_buf.mad;
	// 查找cm id
	cm_id_priv = cm_acquire_id(
		cpu_to_be32(IBA_GET(CM_DREP_REMOTE_COMM_ID, drep_msg)),
		cpu_to_be32(IBA_GET(CM_DREP_LOCAL_COMM_ID, drep_msg)));
	if (!cm_id_priv) return -EINVAL;

	work->cm_event.private_data = IBA_GET_MEM_PTR(CM_DREP_PRIVATE_DATA, drep_msg);

	spin_lock_irq(&cm_id_priv->lock);
	if (cm_id_priv->id.state != IB_CM_DREQ_SENT &&
	    cm_id_priv->id.state != IB_CM_DREQ_RCVD) {
		spin_unlock_irq(&cm_id_priv->lock);
		goto out;
	}
	cm_enter_timewait(cm_id_priv);
	// 取消mad
	ib_cancel_mad(cm_id_priv->msg);
	cm_queue_work_unlock(cm_id_priv, work);
	return 0;
out:
	cm_deref_id(cm_id_priv);
	return -EINVAL;
}
```

`ib_cancel_mad`取消发送的MAD操作。如下：

```c
// file: include/rdma/ib_mad.h
static inline void ib_cancel_mad(struct ib_mad_send_buf *send_buf)
{
	ib_modify_mad(send_buf, 0);
}
```

##### 2. iWARP断开连接的过程

iWARP通过`iw_cm_disconnect`断开连接，如下：

```c
// file: drivers/infiniband/core/iwcm.c
int iw_cm_disconnect(struct iw_cm_id *cm_id, int abrupt)
{
	struct iwcm_id_private *cm_id_priv;
	unsigned long flags;
	int ret = 0;
	struct ib_qp *qp = NULL;

	cm_id_priv = container_of(cm_id, struct iwcm_id_private, id);
	wait_event(cm_id_priv->connect_wait, !test_bit(IWCM_F_CONNECT_WAIT, &cm_id_priv->flags));

	spin_lock_irqsave(&cm_id_priv->lock, flags);
	switch (cm_id_priv->state) {
	case IW_CM_STATE_ESTABLISHED:
		// 状态转换为`IW_CM_STATE_CLOSING`
		cm_id_priv->state = IW_CM_STATE_CLOSING;
		if (cm_id_priv->qp)
			qp = cm_id_priv->qp;
		else
			ret = -EINVAL;
		break;
	case IW_CM_STATE_LISTEN:
		ret = -EINVAL;
		break;
	case IW_CM_STATE_CLOSING:
	case IW_CM_STATE_IDLE:
		break;
	case IW_CM_STATE_CONN_RECV:
		break;
	case IW_CM_STATE_CONN_SENT:
	default:
		BUG();
	}
	spin_unlock_irqrestore(&cm_id_priv->lock, flags);

	if (qp) {
		if (abrupt)
			// 修改QP状态为`IB_QP_STATE_ERR`
			ret = iwcm_modify_qp_err(qp);
		else
			// 修改QP状态为`IB_QP_STATE_SQD`
			ret = iwcm_modify_qp_sqd(qp);
		ret = 0;
	}
	return ret;
}
```

## 4 总结

通过本文，我们以`rdma_server`和`rdma_client`示例分析了使用CM进行RDMA通信的基本原理和实现。我们详细分析了`cm`接口的实现机制，包括`cm`事件处理过程和`cm`连接事件处理过程。通过本文的分析，我们可以更好地理解`librdmacm`的工作原理。

## 参考资料

* [RDMA杂谈](https://zhuanlan.zhihu.com/p/164908617)
* [RDMA之基于CM API的QP间建链](https://zhuanlan.zhihu.com/p/494826608)

## 安装测试环境

### 组件版本
- k8s v1.15.3
- docker 18.09.6-ce
- Etcd 3.3.13
- Flanneld 0.11.0
- 插件：
  - Coredns
  - Dashboard
  - Metrics-server
  - EFK (elasticsearch、fluentd、kibana)

### 01 系统初始化和全局变量

```shell
cat >> /etc/hosts <<EOF
10.172.248.40 10-172-248-40
EOF
# 添加账户
useradd -m docker
# 配置ssh免登
ssh-keygen -t rsa
ssh-copy-id root@10.172.248.40

# 因为/root目录磁盘不够，后续注意将全部软件安装套/home下
echo 'PATH=/home/k8s/bin:$PATH' >>/root/.bashrc
source /root/.bashrc
# 安装依赖包
yum install -y epel-release
yum install -y conntrack ntpdate ntp ipvsadm ipset jq iptables curl sysstat libseccomp wget
# 关闭防火墙，清理防火墙规则，设置默认转发策略
systemctl stop firewalld
systemctl disable firewalld
iptables -F && iptables -X && iptables -F -t nat && iptables -X -t nat
iptables -P FORWARD ACCEPT

# 关闭swap分区
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
# 关闭Selinux
setenforce 0
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
# 关闭dnsmasq
systemctl stop dnsmasq
systemctl disable dnsmasq

modprobe ip_vs_rr
modprobe br_netfilter

# 优化内核参数，其中有几个会报无效参数的错，不知有否影响
cat > kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
net.ipv4.tcp_tw_recycle=0
vm.swappiness=0 # 禁止使用 swap 空间，只有当系统 OOM 时才允许使用它
vm.overcommit_memory=1 # 不检查物理内存是否够用
vm.panic_on_oom=0 # 开启 OOM
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
net.netfilter.nf_conntrack_max=2310720
EOF
cp kubernetes.conf  /etc/sysctl.d/kubernetes.conf
sysctl -p /etc/sysctl.d/kubernetes.conf

# 关闭无关服务
systemctl stop postfix && systemctl disable postfix

mkdir /var/log/journal
mkdir /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-prophet.conf <<EOF
[Journal]
# 持久化保存到磁盘
Storage=persistent

# 压缩历史日志
Compress=yes

SyncIntervalSec=5m
RateLimitInterval=30s
RateLimitBurst=1000

# 最大占用空间 1G
SystemMaxUse=1G

# 单日志文件最大 200M
SystemMaxFileSize=200M

# 日志保存时间 2 day
MaxRetentionSec=2day

# 不将日志转发到 syslog
ForwardToSyslog=no
EOF
systemctl restart systemd-journald

# 创建相关目录
mkdir -p  /home/k8s/{bin,work} /etc/{kubernetes,etcd}/cert

# docker和内核为3.10的版本，在容器频繁启停时，会造成cgroup内存泄漏的问题，说是可以升级内核到4.4解决，但内部貌似升级不了，比较蛋疼

#这里采用升级内核的解决办法：
rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
# 安装完成后检查 /boot/grub2/grub.cfg 中对应内核 menuentry 中是否包含 initrd16 配置，如果没有，再安装一次！
yum --enablerepo=elrepo-kernel install -y kernel-lt
# 设置开机从新内核启动
grub2-set-default 0
#安装内核源文件（可选，在升级完内核并重启机器后执行）:
yum --enablerepo=elrepo-kernel install kernel-lt-devel-$(uname -r) kernel-lt-headers-$(uname -r)


cp /etc/default/grub{,.bak}
vim /etc/default/grub # 在 GRUB_CMDLINE_LINUX 一行添加 `numa=off` 参数

cp /boot/grub2/grub.cfg{,.bak}
grub2-mkconfig -o /boot/grub2/grub.cfg

```
> environment.sh

```shell
#!/usr/bin/bash

# 生成 EncryptionConfig 所需的加密 key
export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

# 集群各机器 IP 数组
export NODE_IPS=(10.172.248.40)

# 集群各 IP 对应的主机名数组
export NODE_NAMES=(10-172-248-40)

# etcd 集群服务地址列表
export ETCD_ENDPOINTS="https://10.172.248.40:2379"

# etcd 集群间通信的 IP 和端口
export ETCD_NODES="10-172-248-40=https://10.172.248.40:2380"

# kube-apiserver 的反向代理(kube-nginx)地址端口
export KUBE_APISERVER="https://127.0.0.1:8443"

# 节点间互联网络接口名称
export IFACE="eth0"

# etcd 数据目录
export ETCD_DATA_DIR="/home/data/k8s/etcd/data"

# etcd WAL 目录，建议是 SSD 磁盘分区，或者和 ETCD_DATA_DIR 不同的磁盘分区
export ETCD_WAL_DIR="/home/data/k8s/etcd/wal"

# k8s 各组件数据目录
export K8S_DIR="/home/data/k8s/k8s"

# docker 数据目录
export DOCKER_DIR="/home/data/k8s/docker"

## 以下参数一般不需要修改

# TLS Bootstrapping 使用的 Token，可以使用命令 head -c 16 /dev/urandom | od -An -t x | tr -d ' ' 生成
BOOTSTRAP_TOKEN="41f7e4ba8b7be874fcff18bf5cf41a7c"

# 最好使用 当前未用的网段 来定义服务网段和 Pod 网段

# 服务网段，部署前路由不可达，部署后集群内路由可达(kube-proxy 保证)
SERVICE_CIDR="10.254.0.0/16"

# Pod 网段，建议 /16 段地址，部署前路由不可达，部署后集群内路由可达(flanneld 保证)
CLUSTER_CIDR="172.30.0.0/16"

# 服务端口范围 (NodePort Range)
export NODE_PORT_RANGE="30000-32767"

# flanneld 网络配置前缀
export FLANNEL_ETCD_PREFIX="/kubernetes/network"

# kubernetes 服务 IP (一般是 SERVICE_CIDR 中第一个IP)
export CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"

# 集群 DNS 服务 IP (从 SERVICE_CIDR 中预分配)
export CLUSTER_DNS_SVC_IP="10.254.0.2"

# 集群 DNS 域名（末尾不带点号）
export CLUSTER_DNS_DOMAIN="cluster.local"

# 将二进制目录 /opt/k8s/bin 加到 PATH 中
export PATH=/home/k8s/bin:$PATH
```
```shell
source environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp environment.sh root@${node_ip}:/home/k8s/bin/
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done


sudo mkdir -p /home/k8s/cert && cd /home/k8s
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
mv cfssl_linux-amd64 /home/k8s/bin/cfssl

wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
mv cfssljson_linux-amd64 /home/k8s/bin/cfssljson

wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
mv cfssl-certinfo_linux-amd64 /home/k8s/bin/cfssl-certinfo

chmod +x /home/k8s/bin/*
export PATH=/home/k8s/bin:$PATH


cd /home/k8s/work
cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
EOF

cat > ca-csr.json <<EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ],
  "ca": {
    "expiry": "876000h"
 }
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca
ls ca*


source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/kubernetes/cert"
    scp ca*.pem ca-config.json root@${node_ip}:/etc/kubernetes/cert
  done

sftp -oPort=8000 mayuefei@fswap.sys.xx.com
get kubernetes-client-linux-amd64.tar.gz
tar -xzvf kubernetes-client-linux-amd64.tar.gz

source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/client/bin/kubectl root@${node_ip}:/home/k8s/bin/
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done

cd /opt/k8s/work
cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cd /home/k8s/work
cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes admin-csr.json | cfssljson -bare admin
ls admin*


cd /home/k8s/work
source /home/k8s/bin/environment.sh

# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/home/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kubectl.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=/home/k8s/work/admin.pem \
  --client-key=/home/k8s/work/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=kubectl.kubeconfig

# 设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=kubectl.kubeconfig

# 设置默认上下文
kubectl config use-context kubernetes --kubeconfig=kubectl.kubeconfig


for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ~/.kube"
    scp kubectl.kubeconfig root@${node_ip}:~/.kube/config
  done


# etcd
sftp -oPort=8000 mayuefei@fswap.sys.xx.com
get etcd-v3.3.13-linux-amd64.tar.gz
tar -xvf etcd-v3.3.13-linux-amd64.tar.gz

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp etcd-v3.3.13-linux-amd64/etcd* root@${node_ip}:/home/k8s/bin
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done

cat > etcd-csr.json <<EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "10.172.248.40"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
    -ca-key=/home/k8s/work/ca-key.pem \
    -config=/home/k8s/work/ca-config.json \
    -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
ls etcd*pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/etcd/cert"
    scp etcd*.pem root@${node_ip}:/etc/etcd/cert/
  done

cat > etcd.service.template <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=${ETCD_DATA_DIR}
ExecStart=/home/k8s/bin/etcd \\
  --data-dir=${ETCD_DATA_DIR} \\
  --wal-dir=${ETCD_WAL_DIR} \\
  --name=##NODE_NAME## \\
  --cert-file=/etc/etcd/cert/etcd.pem \\
  --key-file=/etc/etcd/cert/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-cert-file=/etc/etcd/cert/etcd.pem \\
  --peer-key-file=/etc/etcd/cert/etcd-key.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --listen-peer-urls=https://##NODE_IP##:2380 \\
  --initial-advertise-peer-urls=https://##NODE_IP##:2380 \\
  --listen-client-urls=https://##NODE_IP##:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://##NODE_IP##:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --auto-compaction-mode=periodic \\
  --auto-compaction-retention=1 \\
  --max-request-bytes=33554432 \\
  --quota-backend-bytes=6442450944 \\
  --heartbeat-interval=250 \\
  --election-timeout=2000
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

source /home/k8s/bin/environment.sh
for (( i=0; i < 1; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" etcd.service.template > etcd-${NODE_IPS[i]}.service 
  done
ls *.service

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp etcd-${node_ip}.service root@${node_ip}:/etc/systemd/system/etcd.service
  done

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${ETCD_DATA_DIR} ${ETCD_WAL_DIR}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable etcd && systemctl restart etcd " &
  done

systemctl status etcd
journalctl -u etcd

ETCDCTL_API=3 /home/k8s/bin/etcdctl \
    --endpoints=https://10.172.248.40:2379 \
    --cacert=/etc/kubernetes/cert/ca.pem \
    --cert=/etc/etcd/cert/etcd.pem \
    --key=/etc/etcd/cert/etcd-key.pem endpoint health

ETCDCTL_API=3 /home/k8s/bin/etcdctl \
  -w table --cacert=/etc/kubernetes/cert/ca.pem \
  --cert=/etc/etcd/cert/etcd.pem \
  --key=/etc/etcd/cert/etcd-key.pem \
  --endpoints=${ETCD_ENDPOINTS} endpoint status 

# flannel 实现pod网络互通
mkdir flannel
sftp -oPort=8000 mayuefei@fswap.sys.xx.com
get flannel-v0.11.0-linux-amd64.tar.gz
tar -xzvf flannel-v0.11.0-linux-amd64.tar.gz -C flannel

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp flannel/{flanneld,mk-docker-opts.sh} root@${node_ip}:/home/k8s/bin/
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done

cat > flanneld-csr.json <<EOF
{
  "CN": "flanneld",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld
ls flanneld*pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/flanneld/cert"
    scp flanneld*.pem root@${node_ip}:/etc/flanneld/cert
  done

etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/home/k8s/work/ca.pem \
  --cert-file=/home/k8s/work/flanneld.pem \
  --key-file=/home/k8s/work/flanneld-key.pem \
  mk ${FLANNEL_ETCD_PREFIX}/config '{"Network":"'${CLUSTER_CIDR}'", "SubnetLen": 21, "Backend": {"Type": "vxlan"}}'

cat > flanneld.service << EOF
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
ExecStart=/home/k8s/bin/flanneld \\
  -etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  -etcd-certfile=/etc/flanneld/cert/flanneld.pem \\
  -etcd-keyfile=/etc/flanneld/cert/flanneld-key.pem \\
  -etcd-endpoints=${ETCD_ENDPOINTS} \\
  -etcd-prefix=${FLANNEL_ETCD_PREFIX} \\
  -iface=${IFACE} \\
  -ip-masq
ExecStartPost=/home/k8s/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp flanneld.service root@${node_ip}:/etc/systemd/system/
  done

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable flanneld && systemctl restart flanneld"
  done

systemctl status flanneld
journalctl -u flanneld

etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/config

etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets

wget http://nginx.org/download/nginx-1.15.3.tar.gz
tar -xzvf nginx-1.15.3.tar.gz

cd /home/k8s/work/nginx-1.15.3
mkdir nginx-prefix
./configure --with-stream --without-http --prefix=$(pwd)/nginx-prefix --without-http_uwsgi_module --without-http_scgi_module --without-http_fastcgi_module
make && make install

./nginx-prefix/sbin/nginx -v
ldd ./nginx-prefix/sbin/nginx


cd /home/k8s/work
source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    mkdir -p /home/k8s/kube-nginx/{conf,logs,sbin}
  done

cd /home/k8s/work
source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /home/k8s/kube-nginx/{conf,logs,sbin}"
    scp /home/k8s/work/nginx-1.15.3/nginx-prefix/sbin/nginx  root@${node_ip}:/home/k8s/kube-nginx/sbin/kube-nginx
    ssh root@${node_ip} "chmod a+x /home/k8s/kube-nginx/sbin/*"
  done

cat > kube-nginx.conf << EOF
worker_processes 1;

events {
    worker_connections  1024;
}

stream {
    upstream backend {
        hash $remote_addr consistent;
        server 10.172.248.40:6443        max_fails=3 fail_timeout=30s;
    }

    server {
        listen 127.0.0.1:8443;
        proxy_connect_timeout 1s;
        proxy_pass backend;
    }
}
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-nginx.conf  root@${node_ip}:/home/k8s/kube-nginx/conf/kube-nginx.conf
  done

cat > kube-nginx.service <<EOF
[Unit]
Description=kube-apiserver nginx proxy
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStartPre=/home/k8s/kube-nginx/sbin/kube-nginx -c /home/k8s/kube-nginx/conf/kube-nginx.conf -p /home/k8s/kube-nginx -t
ExecStart=/home/k8s/kube-nginx/sbin/kube-nginx -c /home/k8s/kube-nginx/conf/kube-nginx.conf -p /home/k8s/kube-nginx
ExecReload=/home/k8s/kube-nginx/sbin/kube-nginx -c /home/k8s/kube-nginx/conf/kube-nginx.conf -p /home/k8s/kube-nginx -s reload
PrivateTmp=true
Restart=always
RestartSec=5
StartLimitInterval=0
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-nginx.service  root@${node_ip}:/etc/systemd/system/
  done

systemctl daemon-reload && systemctl enable kube-nginx && systemctl restart kube-nginx

# Master
cd /home/k8s/work
sftp -oPort=8000 mayuefei@fswap.sys.xx.com
get kubernetes-server-linux-amd64.tar.tar
tar -xzvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes
tar -xzvf  kubernetes-src.tar.gz

cd /home/k8s/work
source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/server/bin/{apiextensions-apiserver,cloud-controller-manager,kube-apiserver,kube-controller-manager,kube-proxy,kube-scheduler,kubeadm,kubectl,kubelet,mounter} root@${node_ip}:/home/k8s/bin/
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done

# api-server
cd /home/k8s/work
source /home/k8s/bin/environment.sh
cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "10.172.248.40",
    "${CLUSTER_KUBERNETES_SVC_IP}",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
ls kubernetes*pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/kubernetes/cert"
    scp kubernetes*.pem root@${node_ip}:/etc/kubernetes/cert/
  done

cat > encryption-config.yaml <<EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp encryption-config.yaml root@${node_ip}:/etc/kubernetes/
  done

cat > audit-policy.yaml <<EOF
apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
  # The following requests were manually identified as high-volume and low-risk, so drop them.
  - level: None
    resources:
      - group: ""
        resources:
          - endpoints
          - services
          - services/status
    users:
      - 'system:kube-proxy'
    verbs:
      - watch

  - level: None
    resources:
      - group: ""
        resources:
          - nodes
          - nodes/status
    userGroups:
      - 'system:nodes'
    verbs:
      - get

  - level: None
    namespaces:
      - kube-system
    resources:
      - group: ""
        resources:
          - endpoints
    users:
      - 'system:kube-controller-manager'
      - 'system:kube-scheduler'
      - 'system:serviceaccount:kube-system:endpoint-controller'
    verbs:
      - get
      - update

  - level: None
    resources:
      - group: ""
        resources:
          - namespaces
          - namespaces/status
          - namespaces/finalize
    users:
      - 'system:apiserver'
    verbs:
      - get

  # Don't log HPA fetching metrics.
  - level: None
    resources:
      - group: metrics.k8s.io
    users:
      - 'system:kube-controller-manager'
    verbs:
      - get
      - list

  # Don't log these read-only URLs.
  - level: None
    nonResourceURLs:
      - '/healthz*'
      - /version
      - '/swagger*'

  # Don't log events requests.
  - level: None
    resources:
      - group: ""
        resources:
          - events

  # node and pod status calls from nodes are high-volume and can be large, don't log responses for expected updates from nodes
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    users:
      - kubelet
      - 'system:node-problem-detector'
      - 'system:serviceaccount:kube-system:node-problem-detector'
    verbs:
      - update
      - patch

  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - nodes/status
          - pods/status
    userGroups:
      - 'system:nodes'
    verbs:
      - update
      - patch

  # deletecollection calls can be large, don't log responses for expected namespace deletions
  - level: Request
    omitStages:
      - RequestReceived
    users:
      - 'system:serviceaccount:kube-system:namespace-controller'
    verbs:
      - deletecollection

  # Secrets, ConfigMaps, and TokenReviews can contain sensitive & binary data,
  # so only log at the Metadata level.
  - level: Metadata
    omitStages:
      - RequestReceived
    resources:
      - group: ""
        resources:
          - secrets
          - configmaps
      - group: authentication.k8s.io
        resources:
          - tokenreviews
  # Get repsonses can be large; skip them.
  - level: Request
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
    verbs:
      - get
      - list
      - watch

  # Default level for known APIs
  - level: RequestResponse
    omitStages:
      - RequestReceived
    resources:
      - group: ""
      - group: admissionregistration.k8s.io
      - group: apiextensions.k8s.io
      - group: apiregistration.k8s.io
      - group: apps
      - group: authentication.k8s.io
      - group: authorization.k8s.io
      - group: autoscaling
      - group: batch
      - group: certificates.k8s.io
      - group: extensions
      - group: metrics.k8s.io
      - group: networking.k8s.io
      - group: policy
      - group: rbac.authorization.k8s.io
      - group: scheduling.k8s.io
      - group: settings.k8s.io
      - group: storage.k8s.io
      
  # Default level for all other requests.
  - level: Metadata
    omitStages:
      - RequestReceived
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp audit-policy.yaml root@${node_ip}:/etc/kubernetes/audit-policy.yaml
  done

cat > proxy-client-csr.json <<EOF
{
  "CN": "aggregator",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem  \
  -config=/etc/kubernetes/cert/ca-config.json  \
  -profile=kubernetes proxy-client-csr.json | cfssljson -bare proxy-client
ls proxy-client*.pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp proxy-client*.pem root@${node_ip}:/etc/kubernetes/cert/
  done

cat > kube-apiserver.service.template <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=${K8S_DIR}/kube-apiserver
ExecStart=/home/k8s/bin/kube-apiserver \\
  --advertise-address=##NODE_IP## \\
  --default-not-ready-toleration-seconds=360 \\
  --default-unreachable-toleration-seconds=360 \\
  --feature-gates=DynamicAuditing=true \\
  --max-mutating-requests-inflight=2000 \\
  --max-requests-inflight=4000 \\
  --default-watch-cache-size=200 \\
  --delete-collection-workers=2 \\
  --encryption-provider-config=/etc/kubernetes/encryption-config.yaml \\
  --etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  --etcd-certfile=/etc/kubernetes/cert/kubernetes.pem \\
  --etcd-keyfile=/etc/kubernetes/cert/kubernetes-key.pem \\
  --etcd-servers=${ETCD_ENDPOINTS} \\
  --bind-address=##NODE_IP## \\
  --secure-port=6443 \\
  --tls-cert-file=/etc/kubernetes/cert/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kubernetes-key.pem \\
  --insecure-port=0 \\
  --audit-dynamic-configuration \\
  --audit-log-maxage=15 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-truncate-enabled \\
  --audit-log-path=${K8S_DIR}/kube-apiserver/audit.log \\
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \\
  --profiling \\
  --anonymous-auth=false \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --enable-bootstrap-token-auth \\
  --requestheader-allowed-names="aggregator" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --service-account-key-file=/etc/kubernetes/cert/ca.pem \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=api/all=true \\
  --enable-admission-plugins=NodeRestriction \\
  --allow-privileged=true \\
  --apiserver-count=1 \\
  --event-ttl=168h \\
  --kubelet-certificate-authority=/etc/kubernetes/cert/ca.pem \\
  --kubelet-client-certificate=/etc/kubernetes/cert/kubernetes.pem \\
  --kubelet-client-key=/etc/kubernetes/cert/kubernetes-key.pem \\
  --kubelet-https=true \\
  --kubelet-timeout=10s \\
  --proxy-client-cert-file=/etc/kubernetes/cert/proxy-client.pem \\
  --proxy-client-key-file=/etc/kubernetes/cert/proxy-client-key.pem \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --service-node-port-range=${NODE_PORT_RANGE} \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=10
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

for (( i=0; i < 1; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-apiserver.service.template > kube-apiserver-${NODE_IPS[i]}.service 
  done
ls kube-apiserver*.service

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-apiserver-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-apiserver.service
  done

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-apiserver"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-apiserver && systemctl restart kube-apiserver"
  done

ETCDCTL_API=3 etcdctl \
    --endpoints=${ETCD_ENDPOINTS} \
    --cacert=/home/k8s/work/ca.pem \
    --cert=/home/k8s/work/etcd.pem \
    --key=/home/k8s/work/etcd-key.pem \
    get /registry/ --prefix --keys-only

kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes

# Controller-manager

cat > kube-controller-manager-csr.json <<EOF
{
    "CN": "system:kube-controller-manager",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "hosts": [
      "127.0.0.1",
      "10.172.248.40"
    ],
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-controller-manager",
        "OU": "4Paradigm"
      }
    ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
ls kube-controller-manager*pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager*.pem root@${node_ip}:/etc/kubernetes/cert/
  done

kubectl config set-cluster kubernetes \
  --certificate-authority=/home/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=kube-controller-manager.pem \
  --client-key=kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-context system:kube-controller-manager \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager.kubeconfig root@${node_ip}:/etc/kubernetes/
  done

cat > kube-controller-manager.service.template <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
WorkingDirectory=${K8S_DIR}/kube-controller-manager
ExecStart=/home/k8s/bin/kube-controller-manager \\
  --profiling \\
  --cluster-name=kubernetes \\
  --controllers=*,bootstrapsigner,tokencleaner \\
  --kube-api-qps=1000 \\
  --kube-api-burst=2000 \\
  --leader-elect \\
  --use-service-account-credentials=true \\
  --concurrent-service-syncs=2 \\
  --bind-address=##NODE_IP## \\
  --secure-port=10252 \\
  --tls-cert-file=/etc/kubernetes/cert/kube-controller-manager.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kube-controller-manager-key.pem \\
  --port=0 \\
  --authentication-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-allowed-names="" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --authorization-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --cluster-signing-cert-file=/etc/kubernetes/cert/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --experimental-cluster-signing-duration=876000h \\
  --horizontal-pod-autoscaler-sync-period=10s \\
  --concurrent-deployment-syncs=10 \\
  --concurrent-gc-syncs=30 \\
  --node-cidr-mask-size=24 \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --pod-eviction-timeout=6m \\
  --terminated-pod-gc-threshold=10000 \\
  --root-ca-file=/etc/kubernetes/cert/ca.pem \\
  --service-account-private-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

for (( i=0; i < 1; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-controller-manager.service.template > kube-controller-manager-${NODE_IPS[i]}.service 
  done
ls kube-controller-manager*.service

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-controller-manager-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-controller-manager.service
  done

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-controller-manager"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-controller-manager && systemctl restart kube-controller-manager"
  done

systemctl status kube-controller-manager
journalctl -u kube-controller-manager

curl -s --cacert /home/k8s/work/ca.pem --cert /home/k8s/work/admin.pem --key /home/k8s/work/admin-key.pem https://10.172.248.40:10252/metrics |head

# Scheduler
cat > kube-scheduler-csr.json <<EOF
{
    "CN": "system:kube-scheduler",
    "hosts": [
      "127.0.0.1",
      "10.172.248.40"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-scheduler",
        "OU": "4Paradigm"
      }
    ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
ls kube-scheduler*pem

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler*.pem root@${node_ip}:/etc/kubernetes/cert/
  done

kubectl config set-cluster kubernetes \
  --certificate-authority=/home/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
  --client-certificate=kube-scheduler.pem \
  --client-key=kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-context system:kube-scheduler \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler.kubeconfig root@${node_ip}:/etc/kubernetes/
  done

cat >kube-scheduler.yaml.template <<EOF
apiVersion: kubescheduler.config.k8s.io/v1alpha1
kind: KubeSchedulerConfiguration
bindTimeoutSeconds: 600
clientConnection:
  burst: 200
  kubeconfig: "/etc/kubernetes/kube-scheduler.kubeconfig"
  qps: 100
enableContentionProfiling: false
enableProfiling: true
hardPodAffinitySymmetricWeight: 1
healthzBindAddress: ##NODE_IP##:10251
leaderElection:
  leaderElect: true
metricsBindAddress: ##NODE_IP##:10251
EOF

for (( i=0; i < 1; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-scheduler.yaml.template > kube-scheduler-${NODE_IPS[i]}.yaml
  done
ls kube-scheduler*.yaml

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler-${node_ip}.yaml root@${node_ip}:/etc/kubernetes/kube-scheduler.yaml
  done

cat > kube-scheduler.service.template <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
WorkingDirectory=${K8S_DIR}/kube-scheduler
ExecStart=/home/k8s/bin/kube-scheduler \\
  --config=/etc/kubernetes/kube-scheduler.yaml \\
  --bind-address=##NODE_IP## \\
  --secure-port=10259 \\
  --port=0 \\
  --tls-cert-file=/etc/kubernetes/cert/kube-scheduler.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kube-scheduler-key.pem \\
  --authentication-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-allowed-names="" \\
  --requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --requestheader-extra-headers-prefix="X-Remote-Extra-" \\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User \\
  --authorization-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF

for (( i=0; i < 1; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-scheduler.service.template > kube-scheduler-${NODE_IPS[i]}.service 
  done
ls kube-scheduler*.service

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kube-scheduler-${node_ip}.service root@${node_ip}:/etc/systemd/system/kube-scheduler.service
  done

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-scheduler"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-scheduler && systemctl restart kube-scheduler"
  done

systemctl status kube-scheduler

# Worker

yum install -y epel-release
yum install -y conntrack ipvsadm ntp ntpdate ipset jq iptables curl sysstat libseccomp && modprobe ip_vs

cd /home/k8s/work
wget https://download.docker.com/linux/static/stable/x86_64/docker-18.09.6.tgz
tar -xvf docker-18.09.6.tgz

source /home/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp docker/*  root@${node_ip}:/home/k8s/bin/
    ssh root@${node_ip} "chmod +x /home/k8s/bin/*"
  done

cat > docker.service <<"EOF"
[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.io

[Service]
WorkingDirectory=##DOCKER_DIR##
Environment="PATH=/home/k8s/bin:/bin:/sbin:/usr/bin:/usr/sbin"
EnvironmentFile=-/run/flannel/docker
ExecStart=/home/k8s/bin/dockerd $DOCKER_NETWORK_OPTIONS
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Delegate=yes
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
# EOF 前后有双引号，这样 bash 不会替换文档中的变量，如 $DOCKER_NETWORK_OPTIONS (这些环境变量是 systemd 负责替换的。)

iptables -P FORWARD ACCEPT
/sbin/iptables -P FORWARD ACCEPT

sed -i -e "s|##DOCKER_DIR##|${DOCKER_DIR}|" docker.service
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp docker.service root@${node_ip}:/etc/systemd/system/
  done

cat > docker-daemon.json <<EOF
{
    "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn","https://hub-mirror.c.163.com"],
    "insecure-registries": ["docker02:35000"],
    "max-concurrent-downloads": 20,
    "live-restore": true,
    "max-concurrent-uploads": 10,
    "debug": true,
    "data-root": "${DOCKER_DIR}/data",
    "exec-root": "${DOCKER_DIR}/exec",
    "log-opts": {
      "max-size": "100m",
      "max-file": "5"
    }
}
EOF

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p  /etc/docker/ ${DOCKER_DIR}/{data,exec}"
    scp docker-daemon.json root@${node_ip}:/etc/docker/daemon.json
  done

systemctl daemon-reload && systemctl enable docker && systemctl restart docker
systemctl status docker
journalctl -u docker

## Kubelet
for node_name in ${NODE_NAMES[@]}
  do
    echo ">>> ${node_name}"

    # 创建 token
    export BOOTSTRAP_TOKEN=$(kubeadm token create \
      --description kubelet-bootstrap-token \
      --groups system:bootstrappers:${node_name} \
      --kubeconfig ~/.kube/config)

    # 设置集群参数
    kubectl config set-cluster kubernetes \
      --certificate-authority=/etc/kubernetes/cert/ca.pem \
      --embed-certs=true \
      --server=${KUBE_APISERVER} \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig

    # 设置客户端认证参数
    kubectl config set-credentials kubelet-bootstrap \
      --token=${BOOTSTRAP_TOKEN} \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig

    # 设置上下文参数
    kubectl config set-context default \
      --cluster=kubernetes \
      --user=kubelet-bootstrap \
      --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig

    # 设置默认上下文
    kubectl config use-context default --kubeconfig=kubelet-bootstrap-${node_name}.kubeconfig
  done

for node_name in ${NODE_NAMES[@]}
  do
    echo ">>> ${node_name}"
    scp kubelet-bootstrap-${node_name}.kubeconfig root@${node_name}:/etc/kubernetes/kubelet-bootstrap.kubeconfig
  done

cat > kubelet-config.yaml.template <<EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: "##NODE_IP##"
staticPodPath: ""
syncFrequency: 1m
fileCheckFrequency: 20s
httpCheckFrequency: 20s
staticPodURL: ""
port: 10250
readOnlyPort: 0
rotateCertificates: true
serverTLSBootstrap: true
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/etc/kubernetes/cert/ca.pem"
authorization:
  mode: Webhook
registryPullQPS: 0
registryBurst: 20
eventRecordQPS: 0
eventBurst: 20
enableDebuggingHandlers: true
enableContentionProfiling: true
healthzPort: 10248
healthzBindAddress: "##NODE_IP##"
clusterDomain: "${CLUSTER_DNS_DOMAIN}"
clusterDNS:
  - "${CLUSTER_DNS_SVC_IP}"
nodeStatusUpdateFrequency: 10s
nodeStatusReportFrequency: 1m
imageMinimumGCAge: 2m
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
volumeStatsAggPeriod: 1m
kubeletCgroups: ""
systemCgroups: ""
cgroupRoot: ""
cgroupsPerQOS: true
cgroupDriver: cgroupfs
runtimeRequestTimeout: 10m
hairpinMode: promiscuous-bridge
maxPods: 220
podCIDR: "${CLUSTER_CIDR}"
podPidsLimit: -1
resolvConf: /etc/resolv.conf
maxOpenFiles: 1000000
kubeAPIQPS: 1000
kubeAPIBurst: 2000
serializeImagePulls: false
evictionHard:
  memory.available:  "100Mi"
nodefs.available:  "10%"
nodefs.inodesFree: "5%"
imagefs.available: "15%"
evictionSoft: {}
enableControllerAttachDetach: true
failSwapOn: true
containerLogMaxSize: 20Mi
containerLogMaxFiles: 10
systemReserved: {}
kubeReserved: {}
systemReservedCgroup: ""
kubeReservedCgroup: ""
enforceNodeAllocatable: ["pods"]
EOF

for node_ip in ${NODE_IPS[@]}
  do 
    echo ">>> ${node_ip}"
    sed -e "s/##NODE_IP##/${node_ip}/" kubelet-config.yaml.template > kubelet-config-${node_ip}.yaml.template
    scp kubelet-config-${node_ip}.yaml.template root@${node_ip}:/etc/kubernetes/kubelet-config.yaml
  done

cat > kubelet.service.template <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=${K8S_DIR}/kubelet
ExecStart=/home/k8s/bin/kubelet \\
  --bootstrap-kubeconfig=/etc/kubernetes/kubelet-bootstrap.kubeconfig \\
  --cert-dir=/etc/kubernetes/cert \\
  --cni-conf-dir=/etc/cni/net.d \\
  --container-runtime=docker \\
  --container-runtime-endpoint=unix:///var/run/dockershim.sock \\
  --root-dir=${K8S_DIR}/kubelet \\
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
  --config=/etc/kubernetes/kubelet-config.yaml \\
  --hostname-override=##NODE_NAME## \\
  --pod-infra-container-image=registry.cn-beijing.aliyuncs.com/images_k8s/pause-amd64:3.1 \\
  --image-pull-progress-deadline=15m \\
  --volume-plugin-dir=${K8S_DIR}/kubelet/kubelet-plugins/volume/exec/ \\
  --logtostderr=true \\
  --v=2
Restart=always
RestartSec=5
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF

for node_name in ${NODE_NAMES[@]}
  do 
    echo ">>> ${node_name}"
    sed -e "s/##NODE_NAME##/${node_name}/" kubelet.service.template > kubelet-${node_name}.service
    scp kubelet-${node_name}.service root@${node_name}:/etc/systemd/system/kubelet.service
  done

kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers

for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kubelet/kubelet-plugins/volume/exec/"
    ssh root@${node_ip} "/usr/sbin/swapoff -a"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kubelet && systemctl restart kubelet"
  done

journalctl -u kubelet |tail
> 日志有报错，但貌似无影响
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.422057   25279 reflector.go:125] k8s.io/kubernetes/pkg/kubelet/kubelet.go:444: Failed to list *v1.Service: Unauthorized
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.422864   25279 reflector.go:125] k8s.io/kubernetes/pkg/kubelet/config/apiserver.go:47: Failed to list *v1.Pod: Unauthorized
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.423674   25279 reflector.go:125] k8s.io/kubernetes/pkg/kubelet/kubelet.go:453: Failed to list *v1.Node: Unauthorized
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.484450   25279 reflector.go:125] k8s.io/client-go/informers/factory.go:133: Failed to list *v1beta1.RuntimeClass: Unauthorized
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.485950   25279 reflector.go:125] k8s.io/client-go/informers/factory.go:133: Failed to list *v1beta1.CSIDriver: Unauthorized
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.492922   25279 kubelet.go:2248] node "10-172-248-40" not found
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.593241   25279 kubelet.go:2248] node "10-172-248-40" not found
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.693548   25279 kubelet.go:2248] node "10-172-248-40" not found
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.793807   25279 kubelet.go:2248] node "10-172-248-40" not found
10月 14 11:28:24 10-172-248-40 kubelet[25279]: E1014 11:28:24.894146   25279 kubelet.go:2248] node "10-172-248-40" not found


cat > csr-crb.yaml <<EOF
 # Approve all CSRs for the group "system:bootstrappers"
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: auto-approve-csrs-for-group
 subjects:
 - kind: Group
   name: system:bootstrappers
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:nodeclient
   apiGroup: rbac.authorization.k8s.io
---
 # To let a node of the group "system:nodes" renew its own credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-client-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:selfnodeclient
   apiGroup: rbac.authorization.k8s.io
---
# A ClusterRole which instructs the CSR approver to approve a node requesting a
# serving cert matching its client cert.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: approve-node-server-renewal-csr
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/selfnodeserver"]
  verbs: ["create"]
---
 # To let a node of the group "system:nodes" renew its own server credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-server-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: approve-node-server-renewal-csr
   apiGroup: rbac.authorization.k8s.io
EOF
kubectl apply -f csr-crb.yaml


# kube-proxy
cat > kube-proxy-csr.json <<EOF
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF

cfssl gencert -ca=/home/k8s/work/ca.pem \
  -ca-key=/home/k8s/work/ca-key.pem \
  -config=/home/k8s/work/ca-config.json \
  -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
ls kube-proxy*

source /home/k8s/bin/environment.sh
kubectl config set-cluster kubernetes \
  --certificate-authority=/home/k8s/work/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=kube-proxy.pem \
  --client-key=kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig

cp kube-proxy.kubeconfig /etc/kubernetes/


cat > kube-proxy-config.yaml.template <<EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clientConnection:
  burst: 200
  kubeconfig: "/etc/kubernetes/kube-proxy.kubeconfig"
  qps: 100
bindAddress: ##NODE_IP##
healthzBindAddress: ##NODE_IP##:10256
metricsBindAddress: ##NODE_IP##:10249
enableProfiling: true
clusterCIDR: ${CLUSTER_CIDR}
hostnameOverride: ##NODE_NAME##
mode: "ipvs"
portRange: ""
kubeProxyIPTablesConfiguration:
  masqueradeAll: false
kubeProxyIPVSConfiguration:
  scheduler: rr
  excludeCIDRs: []
EOF

for (( i=0; i < 1; i++ ))
  do 
    echo ">>> ${NODE_NAMES[i]}"
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" kube-proxy-config.yaml.template > kube-proxy-config-${NODE_NAMES[i]}.yaml.template
    scp kube-proxy-config-${NODE_NAMES[i]}.yaml.template root@${NODE_NAMES[i]}:/etc/kubernetes/kube-proxy-config.yaml
  done

cat > kube-proxy.service <<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=${K8S_DIR}/kube-proxy
ExecStart=/home/k8s/bin/kube-proxy \\
  --config=/etc/kubernetes/kube-proxy-config.yaml \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

for node_name in ${NODE_NAMES[@]}
  do 
    echo ">>> ${node_name}"
    scp kube-proxy.service root@${node_name}:/etc/systemd/system/
  done


for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${K8S_DIR}/kube-proxy"
    ssh root@${node_ip} "modprobe ip_vs_rr"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable kube-proxy && systemctl restart kube-proxy"
  done

# 验证集群功能
kubectl get nodes

# dns插件
cd kubernetes/cluster/addons/dns/coredns/
cp coredns.yaml.base coredns.yaml
sed -i -e "s/__PILLAR__DNS__DOMAIN__/${CLUSTER_DNS_DOMAIN}/" -e "s/__PILLAR__DNS__SERVER__/${CLUSTER_DNS_SVC_IP}/" coredns.yaml
> 会报错，__PILLAR__DNS__MEMORY__LIMIT__ 还需要替换 : 700Mi

# 其他插件，暂未安装

# 清理
https://github.com/opsnull/follow-me-install-kubernetes-cluster/blob/master/12.%E6%B8%85%E7%90%86%E9%9B%86%E7%BE%A4.md
```


## knative installation
### 选择安装istio(支持eventing)和全安装

#### 先装helm
cd /home/k8s/work

wget https://get.helm.sh/helm-v2.14.3-linux-amd64.tar.gz
tar -zxvf helm-v2.14.3-linux-amd64.tar.gz
mv linux-amd64/helm /home/k8s/bin/helm

#### 下面命令会自动安装tiller服务到k8s集群，但是其对应的image在gcr.io，pull不下来
helm init 
#### 需要修改image为 morfies/tiller:2.14.3
kubectl edit deployment tiller-deploy -n kube-system

重新检查
kubectl get pods --namespace kube-system



#### Download and unpack Istio
   export ISTIO_VERSION=1.1.7
   curl -L https://git.io/getLatestIstio | sh -
   cd istio-${ISTIO_VERSION}
#### 安装CRDs，安装前切记要转存镜像
for i in install/kubernetes/helm/istio-init/files/crd*yaml; do kubectl apply -f $i; done

#### 稍等片刻，然后创建ns
cat <<EOF | kubectl apply -f -
   apiVersion: v1
   kind: Namespace
   metadata:
     name: istio-system
     labels:
       istio-injection: disabled
EOF


#### Installing Istio without sidecar injection
 A lighter template, with just pilot/gateway.
 Based on install/kubernetes/helm/istio/values-istio-minimal.yaml
```shell
helm template --namespace=istio-system \
  --set prometheus.enabled=false \
  --set mixer.enabled=false \
  --set mixer.policy.enabled=false \
  --set mixer.telemetry.enabled=false \
  `# Pilot doesn't need a sidecar.` \
  --set pilot.sidecar=false \
  --set pilot.resources.requests.memory=128Mi \
  `# Disable galley (and things requiring galley).` \
  --set galley.enabled=false \
  --set global.useMCP=false \
  `# Disable security / policy.` \
  --set security.enabled=false \
  --set global.disablePolicyChecks=true \
  `# Disable sidecar injection.` \
  --set sidecarInjectorWebhook.enabled=false \
  --set global.proxy.autoInject=disabled \
  --set global.omitSidecarInjectorConfigMap=true \
  `# Set gateway pods to 1 to sidestep eventual consistency / readiness problems.` \
  --set gateways.istio-ingressgateway.autoscaleMin=1 \
  --set gateways.istio-ingressgateway.autoscaleMax=1 \
  `# Set pilot trace sampling to 100%` \
  --set pilot.traceSampling=100 \
  install/kubernetes/helm/istio \
  > ./istio-lean.yaml
```
kubectl apply -f istio-lean.yaml


### 安装knative
mkdir knative-0.8.0
cd knative-0.8.0/

#### 相关文件下载到本地，然后再apply
wget https://github.com/knative/serving/releases/download/v0.8.0/serving.yaml
替换：
```
$cat serving.yaml | grep morfies
  image: morfies/serving-cmd-queue:0.8.0
        image: morfies/serving-cmd-activator:0.8.0
        image: morfies/serving-cmd-autoscaler-hpa:0.8.0
        image: morfies/serving-cmd-autoscaler:0.8.0
  queueSidecarImage: morfies/serving-cmd-queue:0.8.0
        image: morfies/serving-cmd-controller:0.8.0
        image: morfies/serving-cmd-networking-istio:0.8.0
        image: morfies/serving-cmd-webhook:0.8.0
```

wget https://github.com/knative/eventing/releases/download/v0.8.0/release.yaml
```
$cat release.yaml | grep morfies
          value: morfies/eventing-cmd-broker-ingress:0.8.0
          value: morfies/eventing-cmd-broker-filter:0.8.0
        image: morfies/eventing-cmd-controller:0.8.0
          value: morfies/eventing-cmd-cronjob_receive_adapter:0.8.0
          value: morfies/eventing-cmd-apiserver_receive_adapter:0.8.0
        image: morfies/eventing-cmd-sources_controller:0.8.0
        image: morfies/eventing-cmd-webhook:0.8.0
    logging.fluentd-sidecar-image: morfies/fluentd-elasticsearch:2.0.4
        image: morfies/eventing-cmd-in_memory-channel_controller:0.8.0
        image: morfies/eventing-cmd-in_memory-channel_dispatcher:0.8.0
        image: morfies/eventing-cmd-in_memory-controller:0.8.0
        image: morfies/eventing-cmd-in_memory-dispatcher:0.8.0
```
wget https://github.com/knative/serving/releases/download/v0.8.0/monitoring.yaml
```
$cat monitoring.yaml | grep morfies
        image: morfies/elasticsearch:5.6.4
        image: morfies/fluentd-elasticsearch:2.0.4
        image: morfies/addon-resizer:1.7
```

#### first install the CRDs
kubectl apply --selector knative.dev/crd-install=true \
  -f serving.yaml \
  -f release.yaml \
  -f monitoring.yaml
#### complete the install of Knative and its dependencies
kubectl apply -f serving.yaml  \
     -f release.yaml  \
     -f monitoring.yaml

#### check status
   kubectl get pods --all-namespaces  -o wide
   kubectl get pods --namespace knative-eventing  -o wide
   kubectl get pods --namespace knative-monitoring  -o wide

#### 配置service account
参见下面”内部镜像“部分

### 测试ksvc
kubectl apply -f test.yaml
### 调用
curl -d "a=1" -H "HOST: test.default.example.com" http://10.172.248.40:31380

完了会发现很多pod都evicted状态了，describe一下是资源不足，df -u 发现/var/lib/docker/目录不够用，于是，需要转移docker默认的存储位置: https://blog.csdn.net/qijian2003122/article/details/82886989
```shell
systemctl stop docker
# 找个大磁盘
mkdir -p /home/modules/docker/lib
rsync -avz /var/lib/docker/ /home/modules/docker/lib/
mkdir -p /etc/systemd/system/docker.service.d/
vi /etc/systemd/system/docker.service.d/devicemapper.conf
# 文件内容
[Service]
ExecStart=
ExecStart=/opt/kube/bin/dockerd  --graph=/home/modules/docker/lib

# 重启
systemctl daemon-reload
systemctl restart docker
systemctl enable docker

# 发现没用
vi /etc/docker/daemon.json   #直接修改这里的root dir，然后重启就好
```



# 内部镜像
# 先创建imagepullsecret
kubectl create secret docker-registry imghubcred --docker-server=hub.xxx.com --docker-username=xx --docker-password=xx --docker-email=mayuefei@xx.com
# 再patch到现有的default账号里
kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "imghubcred"}]}'
# 检查
kubectl get sa default -o yaml

```yaml
apiVersion: serving.knative.dev/v1alpha1
kind: Service
metadata:
  name: helloworld-nodejs
  namespace: default
spec:
  template:
    metadata:
      name: helloworld-nodejs-first    # revision名，这个也需要规范约定，可以基于此来做流量灰度
    spec:
      serviceAccountName: default
      containers:
      - image: hub.xx.com/xx/helloworld-nodejs:1.0
        env:
        - name: TARGET
          value: "Node.js Sample v1"
        readinessProbe:      # 服务可用的探针配置
          httpGet:
            path: /healthz          # 这样的话，需要wrapper应用中实现这个路由
          initialDelaySeconds: 1
          periodSeconds: 3
          failureThreshold: 10
          timeoutSeconds: 3
#  traffic:
#  - tag: current
#    revisionName: helloworld-nodejs-first
#    percent: 100
#  - tag: latest
#    latestRevision: true
#    percent: 0
```



# 集群运维
参考资料： https://feisky.gitbooks.io/kubernetes/troubleshooting/cluster.html
```shell
kubectl top nodes   # 查看各节点cpu/memory使用量
kubectl cluster-info  # 查看集群组件部署及监听情况
kubectl get componentstatuses  # 执行 kubectl get componentstatuses 命令时，apiserver 默认向 127.0.0.1 发送请求。当 controller-manager、scheduler 以集群模式运行时，有可能和 kube-apiserver 不在一台机器上，这时 controller-manager 或 scheduler 的状态为 Unhealthy，但实际上它们工作正常。
kubectl get pods -o wide  # 可以查看pods的分布情况
# 查看各个组件的日志：
journalctl -l -u kube-apiserver
journalctl -l -u kube-controller-manager
journalctl -l -u kube-scheduler
journalctl -l -u kubelet
journalctl -l -u kube-proxy
```

- `docker ps` 发现没有启动的容器了

重启相关软件后，居然正常了：
```shell
systemctl restart kubelet

systemctl restart kube-apiserver

systemctl restart kube-nginx
```
另外一台机器，能ping通，但dssh 上不去，提示`Resource temporarily unavailable`，其实也是资源消耗完毕了(从kubectl top nodes的表现来看应该就是内存了)，也需要重启，
这次居然很顺利，重启完毕后直接就Ready状态了。

`/var/log/messages` 网上是说这里能看到系统错误相关日志，但我机器上有日志丢失，奇怪，没看到对应时间段的任何日志。


### nodejs的镜像配置规范
主要参考：https://hanhan.pro/2018/06/06/deploy-eggjs-app-with-docker/
eggjs应用的start参数需要去掉`--daemon`参数，让eggjs主进程前台启动，不然容器会认为启动失败
> Docker在构建镜像的时候，是一层一层构建的，仅当这一层有变化时，重新构建对应的层。
> 如果package.json和源代码一起添加到镜像，则每次修改源码都需要重新安装npm模块，这样木有必要。
> 所以，正确的顺序是: 添加package.json；安装npm模块；添加源代码。
这句还没理解，需要查下 docker layer cache 机制， https://docs.semaphoreci.com/article/81-docker-layer-caching 这篇文章的第一节看看就明白了：

```quote
docker是通过layers来构建镜像的，Dockerfile里的每一个命令都会创建新的layer，该layer包含了该命令执行前和执行后所带来的的文件系统变化。
docker通过使用layer cache机制来优化镜像构建的过程，使其更快速。
layer cache机制主要起作用的命令是RUN/COPY/ADD，下面介绍:
- RUN
  RUN命令允许你在镜像里执行一条指令，如果该指令的执行结果所产生的layer已经存在，则这条RUN命令只会执行一次。(ps: 这里可能就是这条指令作为key，layer作为value，记录缓存)
- COPY
  COPY命令允许你拷贝一个或多个文件到镜像，如果COPY命令所涉及的外部文件内容没有变化，layer cache将起作用
  然而，如果有任意一个文件发生变化，即会导致layer cache失效，所有接下来的指令都会全部执行产生新的layer
  因此，需要尽量将COPY命令放到Dockerfile的文件末尾，以保证不必要的重建layer
- ADD
  ADD命令允许你导入文件到镜像，缓存机制和COPY是一致的
- COPY和ADD的区别
  COPY可以在多阶段构建中，将上一阶段的产物拷贝出来，ADD则不能，ADD覆盖了COPY的其他所有能力，然后还多出两个能力：自动解压文件并添加到镜像(直接ADD xx.gz这样既可自动解压)；从url拷贝文件到镜像
```

https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md



#压缩与解压
tar -zcvf archive-name.tar.gz directory-name
tar -zxvf archive-name.tar.gz


systemctl restart kubelet
systemctl restart kube-apiserver
systemctl restart kube-nginx
journalctl -l -u kube-apiserver
journalctl -l -u kube-controller-manager
journalctl -l -u kube-scheduler
journalctl -l -u kubelet
journalctl -l -u kube-proxy


停止所有容器
docker container stop $(docker container ls -aq)
删除所有停止的容器
docker container rm $(docker container ls -aq)

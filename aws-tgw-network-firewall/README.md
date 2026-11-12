# AWS 实验：TGW 多路由表分段 + 集中式 Network Firewall 检查 VPC

> 目标：理解 SAA-C03 里两个高频网络架构
> 1. **Transit Gateway 多路由表分段**（association / propagation）
> 2. **集中式检查 VPC**（inspection VPC）：用路由把出网流量和 VPC 间流量"引"进 AWS Network Firewall（NF）
>
> Region：`ap-southeast-1`，单 AZ（`ap-southeast-1b`）。资源统一使用 `saalab-` 前缀和标签 `Project=saa-lab`。
> 费用大头：NF endpoint、NAT Gateway、4 个 TGW attachment（都按小时计费），做完请立刻按第 8 节清理。

---

## 0. 架构总览

```
                           Internet
                              ▲
                           igw-i
                              │
 ┌───────────── VPC-I 10.4.0.0/16（检查 VPC）──────────────┐
 │  saalab-i-nat 10.4.2.0/24   [NAT GW (Zonal)]            │
 │      RT: 0/0 → igw-i ；10/8 → NF endpoint               │
 │  saalab-i-nf  10.4.1.0/24   [NF endpoint]               │
 │      RT: 0/0 → NAT   ；10/8 → TGW                       │
 │  saalab-i-tgw 10.4.0.0/24   [TGW attachment ENI]        │
 │      RT: 0/0 → NF endpoint                              │
 └────────────────────────┬────────────────────────────────┘
                          │ att-I（关联 full）
                   ┌──────┴──────┐
                   │     TGW     │  tgwrt-full       : 10.1 10.2 10.3 10.4 + 0/0→att-I
                   │             │  tgwrt-restricted : 10.1 10.4           + 0/0→att-I
                   └─┬─────┬───┬─┘
         att-A(full) │     │   │ att-C(restricted)
          ┌──────────┘     │   └──────────┐
   VPC-A 10.1/16     VPC-B 10.2/16     VPC-C 10.3/16
   0/0 → igw-a       0/0 → igw-b       0/0 → TGW（无 IGW）
   10/8 → TGW        10/8 → TGW        10/8 → TGW
```

| VPC | CIDR | 子网 | 角色 |
|---|---|---|---|
| saalab-vpc-a | 10.1.0.0/16 | saalab-a-pub 10.1.0.0/24 | 全互联成员，有 IGW |
| saalab-vpc-b | 10.2.0.0/16 | saalab-b-pub 10.2.0.0/24 | 全互联成员，有 IGW |
| saalab-vpc-c | 10.3.0.0/16 | saalab-c-priv 10.3.0.0/24 | 受限成员：只能访问 A；无 IGW，出网必须经过 NF |
| saalab-vpc-i | 10.4.0.0/16 | saalab-i-tgw 10.4.0.0/24<br>saalab-i-nf 10.4.1.0/24<br>saalab-i-nat 10.4.2.0/24 | 检查 VPC，**三个子网各用一张路由表** |

三个设计目标与实现手段：

| 目标 | 靠什么 |
|---|---|
| A↔B 互通，C 只能到 A | TGW 两张路由表：association 决定"从这个 attachment 进来的包查哪张表"，propagation 决定"我的网段出现在哪些表里" |
| C 上网必须经过防火墙 | C 无 IGW，`0/0 → TGW` → 检查 VPC → NF → NAT → IGW |
| 回程也要经过同一个防火墙 | NAT 子网 `10/8 → NF endpoint`；stateful 防火墙必须看到同一条连接的来回两个方向 |

---

## Part 1 — VPC、子网、IGW、安全组

### 1.1 建 4 个 VPC 和子网
VPC → **Your VPCs → Create VPC** → 选 **VPC only**，按上表填 Name 和 CIDR，加标签 `Project=saa-lab`。
- VPC-C 建好后：Actions → **Edit VPC settings** → 勾 **Enable DNS hostnames**（SSM interface endpoint 的私有 DNS 需要）。

VPC → **Subnets → Create subnet**，按上表建 6 个子网，AZ 全选 `ap-southeast-1b`。
- A、B 的子网：Actions → **Edit subnet settings** → 勾 **Enable auto-assign public IPv4 address**。

### 1.2 IGW
VPC → **Internet gateways → Create**：`saalab-igw-a` / `saalab-igw-b` / `saalab-igw-i`，分别 **Attach to VPC** 到 A / B / I。C 不建 IGW。

### 1.3 路由表
- **A、B**：用 VPC 自带的 main RT，加 `0.0.0.0/0 → igw-a / igw-b`（`10/8 → TGW` 在 Part 2 建完 TGW 后再加）。
- **C**：main RT 先只留 local。
- **VPC-I**：新建 3 张路由表并**显式关联**到对应子网：

  | 路由表 | 关联子网 | 现在要加的路由 |
  |---|---|---|
  | saalab-rt-i-tgw | saalab-i-tgw | 无（只有 local） |
  | saalab-rt-i-nf | saalab-i-nf | 无 |
  | saalab-rt-i-nat | saalab-i-nat | `0.0.0.0/0 → igw-i` |

  VPC-I 的 main RT **只保留 local**，不要往 main RT 上加 `0/0 → igw`。

> **为什么检查 VPC 必须"一个子网一张路由表"**：三个子网对同一目标的下一跳不同（i-tgw 的 0/0 去 NF，i-nf 的 0/0 去 NAT，i-nat 的 0/0 去 IGW；10/8 在 i-nf 去 TGW，在 i-nat 去 NF）。一张路由表里同一个 CIDR 只能有一个下一跳，共用就会做不出来，甚至形成环路。

### 1.4 安全组（每个 VPC 一个，SG 不能跨 VPC）
| SG | 所在 VPC | 入站规则 |
|---|---|---|
| saalab-vpc-a | A | ICMP All 来自 `10.0.0.0/8`；SSH 22 来自 `0.0.0.0/0`（或你的 IP） |
| saalab-vpc-b | B | 同上 |
| saalab-vpc-c | C | ICMP All 来自 `10.0.0.0/8`；SSH 22 来自 `10.0.0.0/8` |
| saalab-c-vpce | C | HTTPS 443 来自 `10.3.0.0/16`（给 SSM endpoint 用） |

### 1.5 VPC-C 的 SSM endpoint（C 没有公网，靠它用 Session Manager 登录）
VPC → **Endpoints → Create endpoint** → AWS services，依次建 3 个：
`com.amazonaws.ap-southeast-1.ssm`、`ssmmessages`、`ec2messages`
- VPC 选 saalab-vpc-c，子网 saalab-c-priv，SG 选 `saalab-c-vpce`，**Enable private DNS name** 勾上。
- Interface endpoint 不会往路由表里加路由（靠 ENI + 私有 DNS 工作）；只有 S3/DynamoDB 的 Gateway endpoint 才会加 prefix list 路由。

---

## Part 2 — TGW 多路由表分段

### 2.1 建 TGW
VPC → **Transit gateways → Create transit gateway**：
- Name `saalab-tgw`，ASN 默认
- **取消勾选** *Default route table association* 和 *Default route table propagation*（要手动控制，这是考点）

### 2.2 建 4 个 attachment
VPC → **Transit gateway attachments → Create**，类型 VPC：

| Attachment | VPC | 子网 |
|---|---|---|
| saalab-tgw-att-a | saalab-vpc-a | saalab-a-pub |
| saalab-tgw-att-b | saalab-vpc-b | saalab-b-pub |
| saalab-tgw-att-c | saalab-vpc-c | saalab-c-priv |
| saalab-tgw-att-i | saalab-vpc-i | **saalab-i-tgw** |

每个约 1 分钟从 pending 变成 available，available 之后才能做关联。

### 2.3 建两张 TGW 路由表并配置关联、传播
VPC → **Transit gateway route tables → Create**：

| 路由表 | Associations（谁查我） | Propagations（谁的网段进我） |
|---|---|---|
| saalab-tgwrt-full | att-a、att-b、att-i | att-a、att-b、att-c、att-i |
| saalab-tgwrt-restricted | att-c | att-a、att-i |

完成后 Routes 标签页应看到：
- full：10.1 / 10.2 / 10.3 / 10.4，全部 propagated
- restricted：10.1 / 10.4（**没有 10.2，所以 C 到不了 B**）

### 2.4 业务 VPC 路由加 `10.0.0.0/8 → saalab-tgw`
A、B、C 的路由表各加一条 `10.0.0.0/8 → Transit Gateway → saalab-tgw`。
- 去本 VPC 时 `10.x/16 local` 比 `10/8` 更长，按最长前缀走 local，不会被 10/8 带偏。

这一步做完后各表状态：

| 路由表 | 路由 |
|---|---|
| A | 10.1.0.0/16 local；10.0.0.0/8 → TGW；0.0.0.0/0 → igw-a |
| B | 10.2.0.0/16 local；10.0.0.0/8 → TGW；0.0.0.0/0 → igw-b |
| C | 10.3.0.0/16 local；10.0.0.0/8 → TGW（**没有 0/0**） |
| saalab-rt-i-tgw / i-nf | 10.4.0.0/16 local |
| saalab-rt-i-nat | 10.4.0.0/16 local；0.0.0.0/0 → igw-i |

### 2.5 启动 3 台测试机
EC2 → Launch instances：AL2023（arm64）、`t4g.micro`、IAM instance profile 选带 `AmazonSSMManagedInstanceCore` 的角色。
- **Network settings → Edit → Select existing security group**，选 Part 1.4 的 SG。不要用向导默认新建的 `launch-wizard-N`（它只放行 22，会导致 ping 全部超时）。

| 实例 | 子网 | SG | 公网 IP |
|---|---|---|---|
| saalab-a | saalab-a-pub | saalab-vpc-a | 开 |
| saalab-b | saalab-b-pub | saalab-vpc-b | 开 |
| saalab-c | saalab-c-priv | saalab-vpc-c | 不开 |

### 2.6 分段测试（Session Manager 登录后执行）
| 测试 | 期望 |
|---|---|
| A `ping <B 私网 IP>` | 通 |
| B `ping <A 私网 IP>` | 通 |
| C `ping <A 私网 IP>` | 通 |
| C `ping <B 私网 IP>` | **100% 丢包**（restricted 表没有 10.2） |

### 2.7 TGW 查表规则（核心理解）
**TGW 只看"包从哪个 attachment 进来"，就查那个 attachment 关联的那张表。** 与目的地无关；去程和回程各自独立查表。

| 流量 | 去程查的表 | 回程查的表 | 结果 |
|---|---|---|---|
| A ↔ B | full（有 10.2） | full（有 10.1） | 通 |
| C → A | restricted（有 10.1） | full（有 10.3） | 通（来回用了两张不同的表） |
| A → C | full（有 10.3） | restricted（有 10.1） | 通 |
| C → B | restricted（**没有 10.2**） | — | 去程直接丢 |
| B → C | full（有 10.3），**包能到 C** | restricted（**没有 10.2**） | 回包被丢 |

一句话：**association 决定"我查哪张表"，propagation 决定"别人的表里有没有我"。**

> 排查顺序：子网路由表 → TGW association / propagation → NACL（无状态，入站出站都要放行）→ SG（有状态，只看入站）。路由都对、ping 却超时，多半是 SG。

---

## Part 3 — Network Firewall + NAT + 检查路径接线

### 3.1 Network Firewall 的三层结构
```
Firewall（saalab-nf）               ← 部署在哪：VPC-I 的 saalab-i-nf 子网，生成一个 endpoint（vpce-xxx）
  └─ Firewall policy（saalab-nf-pol） ← 怎么检查：一个防火墙只绑 1 个策略
       ├─ Stateless 引擎：按单个包处理（类似 NACL）
       └─ Stateful 引擎：按连接处理，能看 HTTP Host / TLS SNI（类似 IPS）
            └─ Rule group（saalab-deny-example-v2） ← 具体规则，可被多个策略复用
```

包的处理顺序：
1. Stateless：没有无状态规则组，走默认动作 **Forward to stateful rule groups**。
2. Stateful（Strict order）：按优先级匹配，命中即执行。
3. 都没命中：走 stateful default action（本实验设为**只告警**，即 `aws:alert_established`，不丢包）。

### 3.2 建规则组（Stateful，Suricata 规则）
Network Firewall → **Rule groups → Create rule group**：
- 类型 **Stateful rule group**，Rule evaluation order **Strict order**，Name `saalab-deny-example-v2`，Capacity `100`
- 规则格式选 **Suricata 兼容的规则字符串**，填入：

```text
drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; dotprefix; content:".example.com"; nocase; endswith; msg:"saalab deny example.com HTTP"; sid:1; rev:1;)
drop tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; dotprefix; content:".example.com"; nocase; endswith; msg:"saalab deny example.com TLS"; sid:2; rev:1;)
```
- 规则组变量 `HOME_NET` = `10.0.0.0/8`

含义：从内网发往外网的 HTTP 请求，Host 以 `.example.com` 结尾（含 example.com 本身和所有子域）就 drop；HTTPS 看的是 TLS ClientHello 里的明文 SNI，不需要解密。

> **坑：不要用 Console 的 "Domain list" 类型。** 2026 版 Console 的 Domain list 只有 HTTP / HTTPS 复选框（不再是 HTTP_HOST / TLS_SNI），生成的是 `aws_route_53_resolved_domain` 规则（按 Route 53 解析出来的 IP 匹配）。它要求策略开启 **Route 53 Resolved IP validation**（还要依赖 DNS Firewall 规则组），否则策略报错 `ROUTE53_RESOLVED_IP_VALIDATION_MISSING`，防火墙一直卡在 PROVISIONING。

### 3.3 建防火墙策略
Network Firewall → **Firewall policies → Create**：
- Name `saalab-nf-pol`
- 选 **Classic**（向导默认是 Next Generation），**取消勾选 Active Threat Defense**（否则会自动加 AttackInfrastructure 托管规则组，占 15000 容量、额外收费）
- Stateless default actions：**Forward to stateful rule groups**（full packets 和 fragmented packets 都选这个）
- Stateful rule evaluation order：**Strict order**（必须和规则组一致，建好不能改）
- Stateful default actions：只选 **Alert established**，**不要选任何 Drop**（选 "Application drop established" 会变成白名单模式，其他网站也会被拦）
- Stream exception policy：Drop（默认）
- Stateful rule groups：添加 `saalab-deny-example-v2`，priority 100
- Policy variables：`HOME_NET` = `10.0.0.0/8`
- Route 53 Resolved IP validation：**不开**

> **HOME_NET 为什么必须改**：规则写的是 `$HOME_NET → $EXTERNAL_NET`。HOME_NET 默认只包含防火墙所在 VPC 的 CIDR（10.4/16），C 的 10.3 不算"内网"，规则就永远匹配不上。

### 3.4 建防火墙
Network Firewall → **Firewalls → Create firewall**：
- Name `saalab-nf`，VPC `saalab-vpc-i`，子网 **saalab-i-nf**（每个 AZ 一个专用的防火墙子网）
- 策略选 `saalab-nf-pol`
- 实验环境把 Delete protection / Subnet change protection 关掉，方便清理

等状态变成 **READY**（约 5 分钟），在详情页记下 **Firewall endpoint ID（vpce-xxx）**。

### 3.5 建 NAT Gateway（Zonal）
VPC → **NAT gateways → Create NAT gateway**：

| 字段 | 值 |
|---|---|
| Name | saalab-nat |
| Availability mode | **Zonal**（新 Console 默认是 Regional，一定要改） |
| Subnet | **saalab-i-nat** |
| Connectivity type | Public |
| Elastic IP | Allocate Elastic IP |

等 Available，记下 `nat-xxx` 和 EIP。

> 为什么不用 Regional NAT：Regional NAT 不在任何子网里，自带一张路由表；检查 VPC 的经典设计（也是考试默认模型）是 Zonal NAT 放在公有子网，用"NAT 子网路由表 `10/8 → NF endpoint`"实现回程对称。

### 3.6 路由接线（7 步，核心）

| # | 位置 | Destination | Target |
|---|---|---|---|
| 1 | saalab-rt-i-tgw | `0.0.0.0/0` | NF endpoint `vpce-xxx`（Target 类型选 *Gateway Load Balancer Endpoint*，NF endpoint 本质就是 GWLB endpoint） |
| 2 | saalab-rt-i-nf | `0.0.0.0/0` | NAT Gateway `nat-xxx` |
| 3 | saalab-rt-i-nf | `10.0.0.0/8` | Transit Gateway `saalab-tgw` |
| 4 | saalab-rt-i-nat | `10.0.0.0/8` | NF endpoint `vpce-xxx` |
| 5 | saalab-tgwrt-full → Routes → Create static route | `0.0.0.0/0` | attachment `saalab-tgw-att-i` |
| 6 | saalab-tgwrt-restricted → Create static route | `0.0.0.0/0` | attachment `saalab-tgw-att-i` |
| 7 | VPC-C 路由表 | `0.0.0.0/0` | Transit Gateway `saalab-tgw` |

A、B 的 `0/0` 继续指向自己的 IGW，不经过 NF，所以 DPI 只在 C 上测。

接线后 VPC-I 三张表的完整内容：
```
saalab-rt-i-tgw : 10.4.0.0/16 local | 0.0.0.0/0 → vpce-xxx
saalab-rt-i-nf  : 10.4.0.0/16 local | 0.0.0.0/0 → nat-xxx | 10.0.0.0/8 → tgw
saalab-rt-i-nat : 10.4.0.0/16 local | 0.0.0.0/0 → igw-i   | 10.0.0.0/8 → vpce-xxx
main RT         : 10.4.0.0/16 local
```

> i-nf 表里不能有 `0/0 → vpce`：防火墙出来的包又被送回自己，形成环路。

**（可选，考点）Appliance mode**：Transit gateway attachments → `saalab-tgw-att-i` → Modify → 勾 **Appliance mode support**。多 AZ 检查 VPC 必须开，保证一条连接的来回两个方向落在同一个 AZ 的防火墙 endpoint；单 AZ 实验不开也能通。

---

## Part 4 — 测试

在 C 上（Session Manager）执行。**curl 一定要加 `-4`**：NF 只检查 IPv4，不加可能走 IPv6 出现假结果。

```bash
curl -4 -sS -m 10 https://checkip.amazonaws.com                              # 返回 NAT 的 EIP
curl -4 -sS -m 10 http://example.com  -o /dev/null -w '%{http_code}\n'      # 超时 = 被 NF 拦截
curl -4 -sS -m 10 https://example.com -o /dev/null -w '%{http_code}\n'      # 超时 = 被 NF 拦截
ping -c 3 <B 私网 IP>                                                         # 接线前不通，接线后通（发夹经过 NF）
```

---

## Part 5 — 流量路径详解

### 5.1 C → `curl https://checkip.amazonaws.com`

**第 0 段：DNS**。C 先向 VPC-C 自己的 Resolver（`10.3.0.2`）查询，走 local，在 VPC-C 内完成。DNS 查询本身不经过 TGW / NF。

**第 1 段：去程（10.3.x.x → checkip 公网 IP:443）**

| 步 | 包所在位置 | 查的表 | 命中路由 | 结果 |
|---|---|---|---|---|
| 1 | VPC-C / saalab-c-priv | C 的 RT | `0/0 → tgw`（目的是公网，10/8 不匹配） | 进 TGW |
| 2 | TGW，从 **att-C** 进 | **restricted** | `0/0 → att-I` | 送往 VPC-I |
| 3 | VPC-I / saalab-i-tgw（att-I 的 ENI 在这个子网） | saalab-rt-i-tgw | `0/0 → vpce` | 进 NF |
| 4 | **NF** | — | SNI = checkip.amazonaws.com，未命中 drop，默认动作只告警 | 放行 |
| 5 | VPC-I / saalab-i-nf（endpoint 在这个子网） | saalab-rt-i-nf | `0/0 → nat` | 进 NAT |
| 6 | NAT | — | 源地址换成 NAT 的私网 IP（10.4.2.x） | — |
| 7 | VPC-I / saalab-i-nat | saalab-rt-i-nat | `0/0 → igw-i` | IGW 把 NAT 私网 IP 1:1 换成 EIP，出公网 |

**第 2 段：回程（checkip → EIP）**

| 步 | 包所在位置 | 查的表 | 命中路由 |
|---|---|---|---|
| 1 | IGW | — | EIP 换回 NAT 私网 IP |
| 2 | NAT | 连接表 | 目的地址还原成 C 的 10.3.x.x |
| 3 | VPC-I / saalab-i-nat | saalab-rt-i-nat | `10/8 → vpce`（10.4/16 local 不匹配 10.3）→ **再进 NF** |
| 4 | NF | — | 识别为同一条连接的回包，放行 |
| 5 | VPC-I / saalab-i-nf | saalab-rt-i-nf | `10/8 → tgw` |
| 6 | TGW，从 **att-I** 进 | **full** | `10.3/16 → att-C`（propagated） |
| 7 | VPC-C / saalab-c-priv | C 的 RT | `10.3/16 local` → 实例（SG 有状态，自动放行回包） |

要点：
- **去程、回程查的 TGW 表不同**：去程从 att-C 进查 restricted，回程从 att-I 进查 full。
- **VPC 内每一跳查哪张表，取决于包当前落在哪个子网**；路由表只在自己的 VPC 内生效（VPC-C 的 `10.3/16 local` 只在包到达 VPC-C 时才生效，在 VPC-I 里查的是 VPC-I 的表）。
- **NF 来回各看到一次同一条连接**；漏了第 4 步接线（i-nat 的 `10/8 → vpce`），回程会绕开 NF，状态不对称，连接异常。
- `curl https://example.com`：前 3 步相同，第 4 步 SNI 命中 drop，curl 超时。

### 5.2 C → `ping B`（东西向发夹）

**去程（echo request）**

| 步 | 包所在位置 | 查的表 | 命中路由 |
|---|---|---|---|
| 1 | VPC-C | C 的 RT | `10/8 → tgw` |
| 2 | TGW，从 att-C 进 | restricted | 没有 10.2 → 落到 `0/0 → att-I`（**C→B 变通的原因**） |
| 3 | VPC-I / saalab-i-tgw | saalab-rt-i-tgw | `0/0 → vpce` |
| 4 | NF | — | ICMP 未命中 http/tls 规则，默认动作只告警，放行 |
| 5 | VPC-I / saalab-i-nf | saalab-rt-i-nf | `10/8 → tgw`（**掉头回 TGW = 发夹**；10/8 比 0/0 更具体，不会去 NAT） |
| 6 | TGW，从 att-I 进 | full | `10.2/16 → att-B` |
| 7 | VPC-B | B 的 RT | `10.2/16 local` → B |

**回程（echo reply）**

| 步 | 包所在位置 | 查的表 | 命中路由 |
|---|---|---|---|
| 1 | VPC-B | B 的 RT | `10/8 → tgw` |
| 2 | TGW，从 att-B 进 | full | `10.3/16 → att-C`（**直接回 C，不经过 NF**） |
| 3 | VPC-C | C 的 RT | `10.3/16 local` → C |

```
去程: C ─att-C→ TGW[restricted 0/0] ─att-I→ NF ─att-I→ TGW[full 10.2] ─att-B→ B
回程: C ←att-C─ TGW[full 10.3] ←att-B──────────────────────────────────────── B
```

要点：
- restricted 表加了 `0/0` 之后，原来的分段被默认路由"打穿"了，变成"经过 NF 的互通"。
- 这条路径**不对称**：NF 只看到 C→B 方向。ICMP 能通；TCP 下 stateful 引擎只看到半条连接，可能被判为异常（本实验未实测）。
- 想重新禁止 C→B：在 NF 上加一条 drop `10.3.0.0/16 ↔ 10.2.0.0/16` 的规则，或者不给 restricted 表加 `0/0`。
- 想让所有 spoke 间流量**来回都**过 NF（AWS 推荐的标准设计）：
  - **spoke 路由表**：A、B、C 都关联它，表里只有 `0/0 → att-I`，不放任何 spoke 明细；
  - **firewall 路由表**：att-I 关联它，所有 spoke 都传播进来；
  - 分段交给 NF 规则，而不是 TGW 路由表。

### 5.3 "路由发夹"是什么
流量的 U 形掉头：包从某个口出去，绕一圈又从同一个口回来，再被转发到别处。
- IDC 里的类比：**单臂路由**（VLAN 间流量从同一根 trunk 上去又下来）、**NAT 回流**（内网访问内网服务器的公网 IP）、**旁挂防火墙 + 策略路由（PBR）引流**。
- 本实验里：C→B 的包从 att-I 出到检查 VPC，过完 NF 又从 att-I 回到 TGW。检查 VPC 就像挂在 TGW 上的"单臂"设备；TGW 多路由表 ≈ VRF，propagation ≈ VRF 之间的路由导入。
- 与单臂路由的区别：NF 在 IP 层透明（不改 IP、不减 TTL），底层用 GENEVE 把包送到后端防火墙集群再送回，原始包头不变。

---

## Part 6 — 常见故障对照

| 现象 | 先查哪里 |
|---|---|
| ping 全部超时，但路由、NACL 都正常 | 实例挂的是 `launch-wizard-N` SG，没放行 ICMP |
| 路由显示 Blackhole / Target 里选不到 TGW | TGW attachment 还没 available |
| 防火墙一直 PROVISIONING，策略报 `ROUTE53_RESOLVED_IP_VALIDATION_MISSING` | 规则组用了 Domain list（`aws_route_53_resolved_domain`），改用 Suricata 规则 |
| example.com 没被拦 | HOME_NET 没改成 `10.0.0.0/8`；或 i-tgw 表没指向 vpce；或 curl 没带 `-4` |
| 所有网站都被拦 | stateful default action 选了 Drop |
| C 上所有 curl 都超时 | 依次查：C 的 `0/0 → tgw` → restricted 表 `0/0 → att-I` → i-tgw `0/0 → vpce` → i-nf `0/0 → nat` → i-nat `0/0 → igw` |
| 能出去回不来 / 时通时不通 | i-nat 缺 `10/8 → vpce`（回程绕开 NF），或 i-nf 缺 `10/8 → tgw` |
| 多 AZ 时偶发断连 | att-I 没开 Appliance mode |

---

## Part 8 — 清理（严格按顺序，NF 最贵最先删）

1. 终止 3 台 EC2。
2. **先删指向 NF endpoint 的路由**（i-tgw 的 `0/0 → vpce`、i-nat 的 `10/8 → vpce`），否则删防火墙会报 endpoint 仍被路由表引用。
3. Network Firewall：删防火墙 `saalab-nf`（等几分钟）→ 删策略 `saalab-nf-pol` → 删规则组 `saalab-deny-example-v2`。如果规则组报 "still in use"，等 1 分钟再删（策略删除有最终一致性延迟）。
4. 删 NAT Gateway → 变成 Deleted 后 **Release** 它的 EIP。
5. 删 VPC-C 的 3 个 SSM endpoint。
6. 删两张 TGW 表里的 static `0/0` → 删 4 个 TGW attachment → 全部 deleted 后删两张 TGW 路由表 → 删 TGW。
7. 每个 VPC：删子网 → 删自建路由表 → 分离并删除 IGW → 删自建 SG → 删 VPC。

确认零残留（Mac 终端）：
```bash
aws network-firewall list-firewalls --region ap-southeast-1
aws network-firewall list-rule-groups --region ap-southeast-1
aws ec2 describe-nat-gateways --region ap-southeast-1 --filter Name=state,Values=available,pending --query 'NatGateways[].NatGatewayId'
aws ec2 describe-addresses --region ap-southeast-1 --query 'Addresses[].PublicIp'
aws ec2 describe-transit-gateways --region ap-southeast-1 --query 'TransitGateways[?State!=`deleted`].TransitGatewayId'
aws ec2 describe-vpcs --region ap-southeast-1 --filters Name=tag:Project,Values=saa-lab --query 'Vpcs[].VpcId'
```

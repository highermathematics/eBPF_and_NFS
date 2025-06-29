# 过程文档

## 一、比赛题目及分析

- **目标描述**：  
  eBPF 提供了对 Linux 内核的增强能力，可以在不改变内核代码的情况下实现对内核功能的扩展，并可以方便地对扩展功能进行卸载而无需重启。网络文件系统（NFS）在服务器端对请求的网络包进行处理后给出对应的响应。结合二者能力可以在内核态就对 NFS 的部分访问进行处理，而无需到达用户态，从而提高 NFS 的整体效率。另外结合 eBPF 的检测能力可以设计实现一个更具安全性的 NFS。  
  
  **本赛题的核心目标是通过 eBPF 技术优化 NFS 网络文件系统的服务性能，并提升其安全性**。具体包括：
  1. **性能优化**：借助 eBPF 的 XDP 技术，在内核网络层拦截 NFS 请求数据包，对部分查询请求直接在内核态完成响应，避免数据包在用户态和内核态间的多次拷贝，从而降低延迟、提升响应速度。
  2. **安全性增强**：利用 eBPF 的内核计算能力，实时监控 NFS 请求的网络行为（如访问频率、操作类型等），并通过 XDP 层实现数据包过滤（如阻断可疑 IP 或异常操作），从而提升 NFS 的访问控制和安全防护能力。

- **设计思路**：
  - **性能优化方案**：
    - 在 XDP（网卡驱动层）部署 eBPF 程序，捕获 NFS 请求数据包。
    - 对于可快速响应的查询请求（如元数据读取），由 XDP 程序直接修改数据包并返回响应，绕过传统内核-用户态交互流程。
    - 响应数据由 TC（流量控制层）的 eBPF 程序动态生成，两者通过 eBPF Maps 共享数据，实现协同处理。
  
  - **安全性增强方案**：
    - 在 XDP 层集成过滤规则，对恶意 IP、异常流量（如高频访问）或越权操作（如非法文件访问）直接丢弃数据包。
    - 结合 eBPF 的统计能力，使用lsm钩子技术与机器学习大模型分析技术结合的方式，实时分析 NFS 操作行为（如读写比例），动态调整安全策略（如限制特定用户的文件操作范围）。

## 二、相关资料调研

### 相关资料

- **总体**
  - [大赛官网](https://os.educg.net/#/sList?TYPE=2025OS_F)
  - [proj108-eBPF-based-NFS](https://github.com/oscomp/proj108-eBPF-based-NFS)
  - [proj293-Fault-Analysis-of-NFS-File-System-Based-on-eBPF](https://github.com/oscomp/proj293-Fault-Analysis-of-NFS-File-System-Based-on-eBPF)
  - [中山大学获奖](https://gitlab.eduxiji.net/kytchett/project788067-87880)

- **eBPF**
  - [eBPF 介绍](https://coolshell.cn/articles/22320.html)
  - [Linux eBPF 解析](https://coolshell.cn/articles/22320.html)
  - [eBPF 在 Ubuntu 上安装](https://yaoyao.io/posts/how-to-setup-ebpf-env-on-ubuntu)

- **NFS**
  - [NFS 介绍与使用](https://blog.csdn.net/mushuangpanny/article/details/127097977)
  - [网络文件系统实时性性能改进浅析](https://kns.cnki.net/kcms2/article/abstract?v=uQzRnDzoTXHp2BhjWBKVAVC6t2KvBO-tyYIT30gDdEgG-o_1yLBqT-wNefB4Ozdfn68LNcZQuc_TzNH_kPkg5e5hKEf5JULhnQKWXF8U-aHMib80RLmpvHm55fClCWF0tcTMEOm5K87uZ07bMYCGoLNh32qcI0gxRGBsftrp5iZoq3wJCLQSQ3pwIJLC1kQb&uniplatform=NZKPT&language=CHS)

- **eBPF && XDP**
  - [Linux eBPF 和 XDP 高速处理数据包；使用 EBPF 编写 XDP 网络过滤器；高性能 ACL](https://blog.csdn.net/Rong_Toa/article/details/108993870)
  - [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/reference-guides/bpf/)
  - [基于 XDP/eBPF 的云网络数据面性能优化研究](https://kns.cnki.net/kcms2/article/abstract?v=uQzRnDzoTXG4vAL7nE3HusvhTTT98SPVDvkfuYoyAh4HEdeLiGAA1p1PXh5x-6_tTQ_04IAH7eUUJw7S-UFMUCec4qY6mhIpRNC--rkjlWR4UplFqegpLhERYACh11fSTbTvMVCRYW6Q-LyXmza_VuqrlLegjoRvucf70rtuTFQOfHjINvdUhYXpZVlpjNsK&uniplatform=NZKPT&language=CHS)

## 三、XDP部分

## 四、LSM+ML部分


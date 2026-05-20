# Kubernetes Overlay Network에서 eBPF 기반 Cross-layer Visibility를 활용한 Lateral Movement 탐지


---

## Overview

### Summary

Kubernetes 클러스터 내부에서 공격자가 컨테이너 간을 이동하는 행위(Lateral Movement)를, 기존 도구가 보지 못하던 네트워크 레이어를 eBPF로 탐지한다.

### 핵심 개념

#### Kubernetes Overlay Network

Kubernetes는 클러스터 내 Pod(컨테이너 묶음) 간 통신을 위해 **Overlay Network**를 사용한다. VXLAN 같은 기술로 실제 물리 네트워크 위에 가상 네트워크를 한 겹 더 얹는 구조다. Flannel, Calico, Cilium 같은 CNI(Container Network Interface) 플러그인이 이를 구현한다.

문제는 이 Overlay 구조가 패킷을 **캡슐화(encapsulation)** 해서 내부 통신의 맥락을 가린다는 점이다.

```
물리 네트워크에서 보이는 것: node_A → node_B
실제 일어나는 일:           pod_A → pod_B (내부에 숨겨짐)
```

#### eBPF (extended Berkeley Packet Filter)

eBPF는 Linux 커널 내부에서 사용자가 작성한 프로그램을 안전하게 실행하는 기술이다. 커널 소스를 수정하거나 재부팅하지 않고도 네트워크 패킷, 시스템 호출, 프로세스 이벤트를 **커널 수준에서 직접 관측**할 수 있다.

기존 모니터링 도구가 커널을 거친 뒤 이미 분리된 정보를 수집하는 것과 달리, eBPF는 **분리되기 전 커널 안에서** 정보를 가져올 수 있다.

#### Cross-layer Visibility

Overlay 네트워크 환경에서는 정보가 세 레이어에 나뉘어 존재한다.

| 레이어 | 담고 있는 정보 |
|--------|--------------|
| Outer (물리 네트워크) | 어떤 노드(서버)에서 어떤 노드로 |
| Inner (Overlay 내부) | 어떤 Pod에서 어떤 Pod로 |
| Process (커널) | 어떤 프로세스가 연결을 만들었는가 |

기존 도구는 이 세 레이어를 **따로따로** 본다. Cross-layer Visibility란 이 세 레이어를 **하나의 이벤트로 결합**하여 보는 것을 의미하며, eBPF는 커널 수정이나 재부팅 없이 이 결합을 안전하고 실용적으로 구현할 수 있는 사실상 유일한 수단이다.

#### Lateral Movement

공격자가 시스템 하나를 침해한 뒤, 내부 네트워크를 통해 **다른 시스템으로 이동하거나 탐색**하는 행위다. Kubernetes 환경에서는 다음과 같이 나타난다.

- 침해된 Pod에서 다른 Pod의 포트를 스캔
- 접근 권한이 없는 Namespace의 서비스에 접근
- DB나 인증 서버에 직접 연결 시도
- 내부 DNS로 서비스 목록 열거

이 행위는 내부 트래픽이므로 외부 방화벽으로 탐지할 수 없고, 정상 서비스 트래픽과 IP/포트가 겹쳐 기존 IDS로도 구별하기 어렵다.

---

### 본 연구의 목표

> **eBPF로 세 레이어(node, pod, process)의 정보를 커널에서 하나로 묶고, 이를 서비스 의존 그래프와 비교해 정상 통신이 아닌 것을 Lateral Movement로 탐지한다.**

1. **수집**: eBPF hook을 활용해 outer node IP, inner pod IP, process 정보를 단일 이벤트로 correlation
2. **모델링**: 정상 상태의 서비스 의존 그래프(어떤 Pod가 어떤 Pod와 통신해야 하는가)를 구성
3. **탐지**: 수집된 이벤트에서 그래프에 없는 통신 경로, 비정상 프로세스, Namespace 경계 위반을 이상 행위로 판단
4. **검증**: 자체 구축한 Kubernetes VXLAN 환경에서 실제 공격 시나리오를 재현하고 탐지율을 평가

---

## 1. Lateral Movement 키체인 (K8s 맥락)

```
[Initial Access]    취약 이미지 / misconfigured API Server / Ingress 취약점
        ↓
[Execution]         컨테이너 내 RCE, kubectl exec, 웹쉘
        ↓
[Discovery]         ← 탐지 시작 구간
                    내부 Pod IP 대역 스캔, CoreDNS 쿼리, Port Scan
        ↓
[Lateral Movement]  ← 핵심 탐지 대상
                    Pod-to-Pod 이동, Namespace Traversal, 정상 경로 우회
        ↓
[Privilege Escalation / Exfiltration]  ← 범위 밖 (네트워크만으로 탐지 어려움)
```

**탐지 범위**: Discovery → Lateral Movement 구간의 네트워크 트래픽. 패킷/flow 레벨에서 관찰 가능.

---

## 2. Kubernetes 공격 유형 및 탐지 가능 여부

| 공격 유형 | 탐지 가능 여부 | 탐지 신호 |
|---|---|---|
| Pod Network Scan | ✅ | unique_dst_count 급증 |
| Port Scan | ✅ | unique_dst_port_count, port_entropy |
| Namespace Traversal | ✅ | cross_namespace_flag, SDG 이탈 |
| Service Discovery (DNS Abuse) | ✅ | DNS query rate, NXDOMAIN 비율 |
| Abnormal Direct Access | ✅ | 서비스 그래프에 없는 (src, dst) edge |
| Service Account Token Abuse | ⚠️ | API 서버 트래픽 패턴으로 부분 탐지 |
| Container Escape | ❌ | 커널/호스트 레이어, 범위 밖 |
| etcd 직접 접근 | ❌ | 범위 밖 |

---

## 3. 관련 선행 논문 리뷰 (eBPF 미사용)

### [1] Bowman et al. — Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI
*USENIX RAID 2020*

Windows 인증 로그에서 host-to-host 인증 이벤트를 그래프로 구성하고, 비지도 그래프 ML로 비정상 edge를 탐지한다. 라벨 없이 동작한다는 점에서 실환경 적용이 용이하고, 학습된 logistic regression link predictor로 저확률 인증 이벤트를 이상으로 판정한다.

실제 기업 네트워크 데이터에서 실험했으며, lateral movement 시 발생하는 비정상 host 간 인증 패턴을 그래프 구조로 잡아낸다. 다만 Windows Event Log 의존적이라 Linux 컨테이너 환경에는 인증 로그 자체가 없고, Kubernetes Pod/Namespace 맥락을 전혀 다루지 않는다. Overlay encapsulation으로 인한 inner/outer 분리 문제도 고려 대상이 아니다.

### [2] King & Huang — Euler: Detecting Network Lateral Movement via Scalable Temporal Link Prediction
*NDSS 2022 / ACM TOPS 2023*

네트워크 연결 로그를 시간 순서의 스냅샷 그래프로 추상화하고, GNN + RNN 조합으로 비정상 edge를 탐지한다. GNN이 각 시간 스냅샷의 토폴로지를 인코딩하고, RNN이 시간에 따른 변화 패턴을 학습한다. GNN 레이어를 여러 머신에 분산 처리하여 대규모 네트워크에도 적용 가능하다.

경량 alerting 메커니즘을 결합하면 Precision이 0.243에서 0.986으로 크게 향상된다고 보고한다. 그래프 기반 접근으로 연결 이력과 패턴 변화를 함께 포착한다는 점이 강점이다. 그러나 분석 단위가 IP/Port 레벨 flow에 머물러 있어 어떤 프로세스가 연결을 만들었는지, 어느 Pod/Namespace에서 발생했는지는 알 수 없다. K8s Overlay에서 outer IP와 inner IP가 분리되는 문제도 다루지 않는다.

### [3] C-BEDIM / S-BEDIM — Lateral Movement Detection in Enterprise Network through Behavior Deviation Measurement
*Computers & Security, Elsevier, 2023*

정상 구간 트래픽에서 행동 프로파일을 구성한 뒤, 이후 트래픽의 이탈 정도(deviation score)로 lateral movement를 판정한다. C-BEDIM은 connection 단위, S-BEDIM은 session 단위로 프로파일을 만든다. 정상 baseline 대비 deviation이라는 아이디어는 본 연구의 service dependency graph 기반 이탈 탐지와 개념적으로 유사하다.

기업 flat network에서 실험했고, baseline-deviation 방식이 단순 rule보다 새로운 공격 패턴에 유연하게 대응한다는 점을 확인했다. 다만 Kubernetes Namespace나 Pod 맥락 없이 IP/포트 레벨 행동만 다루며, VXLAN encapsulation으로 인한 가시성 문제는 고려하지 않는다.

---

### 선행 연구 vs 본 연구

| | Bowman (2020) | Euler (2022) | C-BEDIM (2023) | 본 연구 |
|---|---|---|---|---|
| 수집 대상 | 인증 로그 | 넷플로우 | 네트워크 flow | eBPF 이벤트 |
| K8s context | ❌ | ❌ | ❌ | ✅ |
| Process context | ❌ | ❌ | ❌ | ✅ |
| Overlay 고려 | ❌ | ❌ | ❌ | ✅ |

---

## 4. 데이터 수집 구체화 — 컨테이너 외부 수집

컨테이너 내부에서 직접 수집하면 컨테이너 삭제 시 에이전트도 사라지고, 이미지마다 주입해야 한다. 따라서 **Node 레벨 eBPF DaemonSet**으로 컨테이너 외부에서 수집한다.

| 수집 계층 | 방법 | 획득 정보 |
|---|---|---|
| Node VXLAN 인터페이스 (flannel.1) | tc hook + VXLAN 헤더 파싱 | outer node IP, inner pod IP, VNI |
| 커널 syscall | kprobe (tcp_connect) | PID, process name, cmdline |
| K8s 메타데이터 | Watch API | pod, namespace, service 매핑 |
| PCAP | tcpdump @ flannel.1 | replay용 raw 패킷 |

---

## 5. 실험 환경 구성

```
┌──────────────────────────────────────────────────────────────────┐
│                 Kubernetes Cluster (kind + Flannel VXLAN)        │
│                                                                  │
│  ┌─────────────────────────┐  ┌─────────────────────────┐       │
│  │      Worker Node 1      │  │      Worker Node 2      │       │
│  │  [frontend-ns]          │  │  [backend-ns]           │       │
│  │   frontend-pod          │  │   backend-pod           │       │
│  │  [attacker-ns]          │  │  [db-ns]  db-pod        │       │
│  │   attacker-pod          │  │                         │       │
│  │                         │  │                         │       │
│  │  ┌─────────────────┐    │  │  ┌─────────────────┐    │       │
│  │  │ eBPF DaemonSet  │    │  │  │ eBPF DaemonSet  │    │       │
│  │  │ (monitoring-ns) │    │  │  │ (monitoring-ns) │    │       │
│  │  │ 컨테이너 외부   │    │  │  │ 컨테이너 외부   │    │       │
│  │  │ tc hook         │    │  │  │ tc hook         │    │       │
│  │  │ kprobe          │    │  │  │ kprobe          │    │       │
│  │  │ tcpdump(PCAP)   │    │  │  │ tcpdump(PCAP)   │    │       │
│  │  └────────┬────────┘    │  │  └────────┬────────┘    │       │
│  └───────────┼─────────────┘  └───────────┼─────────────┘       │
│    ══════════╪══════ VXLAN Overlay (UDP 8472) ══╪════════════    │
└──────────────┼──────────────────────────────────┼───────────────┘
               │  ← 이 지점에서 데이터 수집       │
               └──────────────┬───────────────────┘
                               ▼
                   ┌─────────────────────┐
                   │     중앙 수집기      │
                   │  timestamp 기준 join │
                   │  cross-layer record  │
                   └──────────┬──────────┘
                               ▼
                   ┌─────────────────────┐
                   │      탐지 모듈       │
                   │  SDG 이탈 탐지       │
                   │  Rule-based          │
                   │  ML (RF/XGBoost)     │
                   └─────────────────────┘
```

---

## 6. Lateral Movement PCAP 활용 전략

LM 트래픽을 패킷 레벨에서 먼저 정의하면 K8s 환경 종속성 없이 탐지 모델을 사전 검증할 수 있다.

### LM Packet 판단 기준

패킷/flow 수준에서 아래 조건 중 하나 이상을 만족하면 LM 트래픽으로 간주한다.

| 기준 | 설명 |
|---|---|
| Destination diversity | 단일 출발지에서 단기간 내 다수 목적지 접근 |
| High failure rate | 연결 실패(SYN without SYN-ACK) 비율 과다 — scan 특성 |
| SDG 이탈 | 서비스 그래프에 없는 (src, dst) pair |
| Namespace boundary crossing | 허용되지 않은 namespace 간 통신 |
| Abnormal process | 해당 pod에서 기대되지 않는 process가 연결 생성 |

이 정의는 K8s 환경 밖에서도 적용 가능하다. PCAP 파일에서 위 조건을 만족하는 flow를 LM 후보로 추출할 수 있다.

### PCAP 전략

| 방향 | 설명 |
|---|---|
| A. 기존 PCAP 재활용 | CIC-IDS2017 등에서 scan/infiltration 트래픽 추출 → 탐지 모델 사전 검증 |
| B. K8s 환경 내 직접 생성 | attacker pod에서 nmap/nc 실행, flannel.1에서 tcpdump 캡처 |
| C. PCAP Replay | B에서 생성한 PCAP을 tcpreplay로 재생 → 반복 실험 재현성 확보 |

→ **B + C 조합** 권장: 직접 생성 후 replay로 반복 평가. A는 K8s 무관 사전 검증용.

---

## 7. 설계 허점 및 대안

현재 설계에서 발견된 구조적 문제와 각각의 대안을 정리한다. 구현 전에 이 항목들을 결정해야 한다.

---

### 7.1 수집 레이어

#### [허점 1] PID 기반 join이 컨테이너 환경에서 깨진다

컨테이너마다 독립된 PID namespace를 가지기 때문에 PID가 중복된다.

```
컨테이너 A: PID 1 (nginx)
컨테이너 B: PID 1 (python)  ← 호스트에서 보면 다른 프로세스지만 PID가 같음
```

tc hook(네트워크 이벤트)과 kprobe(프로세스 이벤트)를 PID만으로 join하면 엉뚱한 프로세스와 매핑된다.

**대안:** join 키를 `PID + network namespace inode (netns_ino)` 조합으로 변경. 컨테이너마다 netns_ino가 고유하기 때문에 충돌이 없다. eBPF 내부에서 `bpf_get_current_task()`로 task struct에 접근해 netns_ino를 추출 가능하다.

---

#### [허점 2] tcp_connect kprobe만으로는 UDP 트래픽을 못 잡는다

DNS 쿼리(UDP 53), 일부 gRPC over QUIC가 누락된다. 탐지 대상 공격 중 "Service Discovery (DNS Abuse)"가 DNS 기반인데, 이를 탐지할 수 없다.

**대안:** `udp_sendmsg` 또는 `sys_sendto` kprobe를 추가로 부착해 UDP 이벤트를 별도로 수집한다. DNS의 경우 dst port 53 필터링으로 노이즈를 줄인다.

---

#### [허점 3] tc hook 이벤트와 kprobe 이벤트 간 타이밍 불일치

소켓 생성(kprobe: tcp_connect 발생) → 실제 패킷 전송(tc hook 발생) 사이에 시간 차가 있다. eBPF map에 프로세스 정보를 임시 저장해두고 패킷이 오면 꺼내는 방식인데, 이 사이에 이벤트가 유실되면 매핑에 실패한다.

**대안:** eBPF map에 TTL(만료 시간)을 설정한다. 일정 시간 내에 tc hook 이벤트가 오지 않으면 해당 엔트리를 폐기한다. TTL은 실험적으로 결정 (초기값 1~5초). 매핑 실패 이벤트는 별도로 카운팅해 파이프라인 신뢰도 지표로 활용한다.

---

### 7.2 실험 환경

#### [허점 4] kind는 Docker 위에서 동작해 실제 K8s 환경과 다르다

```
실제 환경: 베어메탈 NIC → VXLAN → pod
kind 환경: 베어메탈 → Docker network → 가상 Node → VXLAN → pod
```

flannel.1 인터페이스가 Docker 브리지 네트워크 위에 올라가기 때문에 tc hook이 잡는 패킷 구조가 실제 환경과 다를 수 있다. "실제 K8s 환경에서 검증했다"는 클레임이 약해진다.

**대안:** VM 기반 멀티노드 클러스터(minikube `--driver=virtualbox/kvm2` 또는 kubeadm)를 사용한다. 로컬 자원이 부족하면 GKE/EKS free tier 또는 학교 서버 활용. kind는 기능 개발 및 빠른 반복 테스트용으로만 사용하고, 논문 실험은 VM 기반에서 진행한다.

---

### 7.3 SDG 설계

#### [허점 5] SDG 학습 기간 기준이 없다

얼마나 오래 정상 트래픽을 관찰해야 SDG가 완성됐다고 볼 수 있는지 정의되지 않았다. 너무 짧으면 정상 edge가 누락되어 오탐이 증가하고, 너무 길면 초기 공격도 정상으로 학습될 수 있다.

**대안:** edge 등장 빈도의 수렴(convergence)을 기준으로 학습 종료를 판단한다. 단위 시간당 새로 등장하는 edge 수가 임계값 이하로 떨어지면 학습 완료로 간주한다. 최소 24시간 + 수렴 조건 동시 충족을 요구한다.

---

#### [허점 6] Pod 재시작 / Rolling Update 시 false positive 폭발

Pod가 새로 뜨면 새 IP를 받는다. SDG에 등록되지 않은 새 pod IP가 통신을 시작하면 전부 이상 탐지된다. 배포 자체가 공격으로 오인된다.

**대안:** K8s Watch API로 Pod 생명주기 이벤트(Created, Running, Deleted)를 실시간으로 구독한다. 새 Pod가 뜨면 해당 Pod의 service 소속을 확인해 SDG에 동적으로 노드를 추가한다. IP 변경 시 기존 노드와 매핑을 유지한다.

```
Watch API 이벤트 → pod_name, namespace, new_ip 추출
                → SDG에서 해당 service 노드 찾아 IP 업데이트
                → 이전 IP 엔트리 TTL 설정 후 만료 처리
```

---

### 7.4 탐지 모델

#### [허점 7] RF/XGBoost는 slow scan을 탐지하지 못한다

단일 이벤트 단위로 분류하는 모델은, 1분에 1개씩 천천히 스캔하는 공격을 정상 트래픽으로 판단한다. 각 이벤트 자체는 정상처럼 보이기 때문이다.

**대안:** 탐지를 두 단계로 구분한다.

| 단계 | 방법 | 탐지 대상 |
|---|---|---|
| 이벤트 레벨 | Rule-based (SDG 이탈, 비정상 프로세스) | 즉시 탐지 가능한 명확한 위반 |
| 집계 레벨 | Sliding window feature + ML | slow scan, 점진적 이동 패턴 |

Sliding window(예: 60초)에서 `unique_dst_count`, `conn_rate`, `port_entropy`를 집계해 시간 축 feature로 만든다. 이 집계 feature를 RF/XGBoost 입력으로 넣으면 slow scan도 탐지 가능하다.

---

### 7.5 PCAP 전략

#### [허점 8] 기존 PCAP(CIC-IDS2017)을 K8s 파이프라인 전체 테스트에 쓸 수 없다

CIC-IDS2017의 IP 주소는 2017년 실험 환경 기준이라 K8s pod IP(`10.244.x.x`)와 다르다. tcpreplay로 흘려보내도 SDG와 매핑이 되지 않아 SDG 이탈 탐지가 작동하지 않는다.

**대안:** 용도를 명확히 분리한다.

| PCAP 종류 | 용도 | 이유 |
|---|---|---|
| CIC-IDS2017 등 기존 PCAP | feature 추출 로직 단위 테스트 | IP 무관하게 패킷 파싱/feature 계산 검증 가능 |
| K8s 환경 직접 생성 PCAP | 파이프라인 전체 통합 테스트 | 실제 pod IP 포함, SDG와 정상 매핑 |

---

### 설계 결정 사항 요약

| 항목 | 현재 설계 | 보완 방향 |
|---|---|---|
| PID join 키 | PID only | PID + netns_ino |
| UDP 수집 | tcp_connect만 | udp_sendmsg 추가 |
| 이벤트 매핑 실패 처리 | 미정 | eBPF map TTL + 실패 카운팅 |
| 실험 클러스터 | kind | VM 기반 (minikube/kubeadm) |
| SDG 학습 종료 기준 | 미정 | edge 수렴 조건 + 최소 24h |
| Pod 재시작 처리 | 미정 | Watch API 연동 동적 SDG 업데이트 |
| slow scan 탐지 | RF 단독 | 이벤트 레벨 + sliding window 집계 2단계 |
| 기존 PCAP 활용 범위 | 혼용 | feature 검증 전용으로 분리 |

---

## References

### Lateral Movement 탐지 (선행 연구)

1. Bowman, B. et al., "Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI," *USENIX RAID 2020*.
   [[USENIX]](https://www.usenix.org/conference/raid2020/presentation/bowman)

2. King, I. J., Huang, H. H., "Euler: Detecting Network Lateral Movement via Scalable Temporal Link Prediction," *NDSS 2022 / ACM TOPS 2023*.
   [[ACM]](https://dl.acm.org/doi/10.1145/3588771) [[PDF]](https://www2.seas.gwu.edu/~howie/publications/Euler-NDSS22.pdf)

3. "C-BEDIM and S-BEDIM: Lateral Movement Detection in Enterprise Network through Behavior Deviation Measurement," *Computers & Security*, 2023.
   [[ScienceDirect]](https://www.sciencedirect.com/science/article/abs/pii/S0167404823001773)

### eBPF 커널 보안

4. He, Y. et al., "Cross Container Attacks: The Bewildered eBPF on Clouds," *USENIX Security*, 2023.
   [[PDF]](https://www.usenix.org/system/files/usenixsecurity23-he.pdf)

5. Fournier, G. et al., "Process level network security monitoring & enforcement with eBPF," *SSTIC*, 2020.
   [[PDF]](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/process_level_network_security_monitoring_and_enfo/SSTIC2020-Article-process_level_network_security_monitoring_and_enforcement_with_ebpf-fournier_Cuzi8wu.pdf)

6. Coppola, M. et al., "eBPF-PATROL," *arXiv:2511.18155*, 2025.
   [[arXiv]](https://arxiv.org/abs/2511.18155)

7. Hamm, L. et al., "Comparative Analysis of eBPF-Based Runtime Security Monitoring," *SCITEPRESS*, 2025.
   [[PDF]](https://www.scitepress.org/Papers/2025/142727/142727.pdf)

### Kubernetes 보안

8. Brignoli, N. et al., "KubeHound: Identifying Attack Paths in Kubernetes Clusters," *Datadog Security Labs*, 2023.
   [[Web]](https://securitylabs.datadoghq.com/articles/kubehound-identify-kubernetes-attack-paths/)

9. Lin, Y. et al., "ShadowKube," *Cybersecurity*, Springer, 2025.
   [[Springer]](https://link.springer.com/article/10.1186/s42400-025-00372-7)

### eBPF 패킷 처리 / VXLAN

10. Vieira, M. et al., "Fast Packet Processing with eBPF and XDP," *UFMG*, 2020.
    [[PDF]](https://homepages.dcc.ufmg.br/~mmvieira/so/papers/Fast_Packet_Processing_with_eBPF_and_XDP.pdf)

11. Mahalingam, M. et al., "RFC 7348 – VXLAN," *IETF*, 2014.
    [[RFC]](https://datatracker.ietf.org/doc/html/rfc7348)

### IDS 데이터셋

12. Sharafaldin, I. et al., "CICIDS2017," *ICISSP*, 2018. [[Dataset]](https://www.unb.ca/cic/datasets/ids-2017.html)
13. Moustafa, N., Slay, J., "UNSW-NB15," *MilCIS*, 2015. [[Dataset]](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
14. Tavallaee, M. et al., "NSL-KDD," *IEEE CISDA*, 2009. [[Dataset]](https://www.unb.ca/cic/datasets/nsl.html)

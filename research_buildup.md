# Kubernetes Overlay Network에서 eBPF 기반 Cross-layer Visibility를 활용한 Lateral Movement 탐지

---

## Overview

### Summary

> Kubernetes 클러스터 내부에서 공격자가 컨테이너 간을 이동하는 행위(Lateral Movement)를, 기존 도구가 보지 못하던 네트워크 레이어를 eBPF로 들여다봄으로써 탐지한다.

---

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

구체적으로:

1. **수집**: eBPF hook을 활용해 outer node IP, inner pod IP, process 정보를 단일 이벤트로 correlation
2. **모델링**: 정상 상태의 서비스 의존 그래프(어떤 Pod가 어떤 Pod와 통신해야 하는가)를 구성
3. **탐지**: 수집된 이벤트에서 그래프에 없는 통신 경로, 비정상 프로세스, Namespace 경계 위반을 이상 행위로 판단
4. **검증**: 자체 구축한 Kubernetes VXLAN 환경에서 실제 공격 시나리오를 재현하고 탐지율을 평가

---

## Research Rationale

---

## 1. Problem Statement

### 1.1 Kubernetes가 자주 공격 당하는 이유

Kubernetes는 현재 클라우드 네이티브 인프라의 사실상 표준으로 자리잡았다. 마이크로서비스 구조에서는 수백 개의 Pod가 클러스터 내부에서 끊임없이 통신하며, 이 내부 통신(East-West traffic)은 외부 트래픽(North-South traffic)보다 훨씬 많은 비중을 차지한다.

이 구조는 공격자 관점에서 매우 유리하다.

- 클러스터 내부는 기본적으로 **신뢰 구역(trusted zone)** 으로 간주됨
- Pod 간 통신은 빈번하고 다양하여 **이상 트래픽을 정상으로 위장하기 쉬움**
- Namespace 경계가 있지만 NetworkPolicy가 없으면 **기본적으로 Pod 간 통신이 허용**됨

공격자는 단 하나의 컨테이너를 침해한 뒤, 내부 서비스를 탐색하고 권한 있는 서비스(DB, 인증 서버, secret 저장소 등)로 이동하는 **Lateral Movement** 전략을 취한다. 이것이 현재 Kubernetes 보안의 핵심 위협이다.

### 1.2 기존 경계 보안 모델의 한계

기존 네트워크 보안은 **경계(perimeter) 보안** 모델에 기반한다. 외부에서 내부로 들어오는 트래픽을 차단하면 안전하다는 가정이다.

그러나 Kubernetes 환경에서는 이 가정이 성립하지 않는다.

| 가정 | 현실 |
|------|------|
| 내부 트래픽은 신뢰할 수 있다 | 침해된 Pod도 내부에서 통신한다 |
| IP 기반으로 출처를 식별할 수 있다 | Pod IP는 수시로 변경된다 |
| 포트 차단으로 이동을 막을 수 있다 | 정상 포트(80, 443, 8080)를 통해 이동한다 |
| 방화벽이 내부 통신을 볼 수 있다 | Overlay Network으로 캡슐화되어 내부가 보이지 않는다 |

이는 Lateral Movement가 기존 방어 체계에서 **탐지하기 가장 어려운 공격 단계**임을 의미한다.

---

## 2. Technical Problem: Visibility Gap in Overlay Networks

### 2.1 Overlay Network 구조

Kubernetes는 Pod 간 통신을 위해 Overlay Network를 사용한다. VXLAN, Geneve 등의 기술로 실제 물리 네트워크 위에 가상 네트워크 레이어를 구성한다.

이 구조에서 패킷은 다음과 같이 이중으로 존재한다.

```
[ Outer Packet ]  (물리 네트워크 레이어)
  src: node_A_IP (192.168.1.10)
  dst: node_B_IP (192.168.1.20)
  └─ [ Inner Packet ]  (Overlay 레이어)
       src: pod_A_IP (10.244.1.5)
       dst: pod_B_IP (10.244.2.8)
       └─ [ Payload ]
            process: pid=1234, comm="python3"
            connection: port=3306
```

### 2.2 가시성 단절이 발생하는 이유

현재 모니터링 도구들은 이 세 레이어를 각각 따로 본다.

| 관측 위치 | 볼 수 있는 정보 | 볼 수 없는 정보 |
|----------|---------------|---------------|
| NIC 수준 (outer) | node IP | pod IP, process |
| Pod 내부 (inner) | pod IP, port | node IP, 캡슐화 맥락 |
| 커널 syscall | process, pid | 어느 pod인지, 네트워크 목적지 |


pod_A 내부의 python3 프로세스(pid 1234)가 node_B의 pod_B에 있는 MySQL(3306)에 접근했는가?

이 질문에 답하려면 세 레이어의 정보를 **단일 이벤트로 결합**해야 하며, 이것이 본 연구가 해결하려는 핵심 기술 문제다.

---

## 3. Limitations of Related Work

### 3.1 eBPF/Cilium 기반 연구의 한계

eBPF와 Cilium은 Kubernetes 네트워킹과 보안 분야에서 핵심 기술로 자리잡았다. 그러나 기존 연구는 주로 다음에 집중한다.

- iptables 대비 패킷 처리 성능 개선
- 네트워크 정책 적용 효율화
- Sidecar 없는 Service Mesh 구현
- Flow 수준의 Observability 제공

이 연구들은 "트래픽을 빠르게 처리하거나 관측하는 것"에는 강점을 가지지만, **Overlay 환경에서 발생하는 공격 흐름을 재구성하여 탐지하는 문제**는 다루지 않는다.

### 3.2 기존 보안 도구와의 비교

현재 eBPF 기반 보안 도구들의 한계를 구체적으로 비교한다.

| 도구 | 관측 범위 | 핵심 한계 |
|------|----------|----------|
| **Falco** | syscall, k8s audit log | Overlay inner/outer 분리 불가, network flow context 부족 |
| **Tetragon** | process + network (L3/L4) | VXLAN encapsulation context 없음, cross-layer correlation 미지원 |
| **Hubble** | Kubernetes flow (L3~L7) | flow record에 process context(pid, comm) 미포함; outer node IP와 inner pod IP를 단일 이벤트로 결합하여 노출하지 않음 |
| **Sysdig** | syscall + container event | Overlay-aware correlation 미지원 |

공통적인 한계는 다음과 같다.

1. **Overlay inner/outer 분리 문제**: outer(node) 맥락과 inner(pod) 맥락을 동시에 가져오지 못함
2. **Process-network 연결 부재**: 어떤 프로세스가 어떤 네트워크 연결을 만들었는지를 Pod 맥락과 함께 결합하지 못함
3. **공격 의미 해석 부재**: 이상 flow를 감지해도 "이것이 Lateral Movement인가"를 자동으로 판단하지 못함

### 3.3 기존 IDS 연구의 한계

기존 IDS 연구에서 사용하는 공개 데이터셋(CICIDS, NSL-KDD, UNSW-NB15 등)은 다음 문제를 가진다.

- Kubernetes Pod/Namespace context 없음
- Container/Process context 없음
- VXLAN Overlay inner/outer 정보 없음
- East-West microservice traffic 구조 미반영
- Service dependency graph 기반 정상/비정상 관계 표현 불가

CICIDS2017 [14], NSL-KDD [16], UNSW-NB15 [15]는 이 분야에서 가장 널리 쓰이는 공개 데이터셋이지만, 세 데이터셋 모두 전통적인 네트워크 환경에서 수집되었으며 위의 다섯 가지 맥락 정보를 포함하지 않는다. 즉, 기존 IDS 연구의 방법론을 그대로 Kubernetes Overlay 환경에 적용하면 **탐지에 필요한 핵심 정보가 처음부터 빠져있다**. 따라서 기존 데이터셋을 그대로 사용하는 것은 불가능하며, Kubernetes VXLAN 환경에서 자체 데이터셋을 구축하는 것이 본 연구의 필수 전제조건이다.

---

## 4. Research Gap

기존 연구를 정리하면 다음 갭이 명확하게 드러난다.

```
[eBPF/Cilium 연구]     → 성능, 정책, observability에 집중
                              ↓ 공격 탐지로 확장 안 됨
[보안 도구 연구]        → syscall 또는 flow 중 하나만 관측
                              ↓ cross-layer correlation 없음
[기존 IDS 연구]         → 전통적 네트워크 환경 기준 데이터셋
                              ↓ Kubernetes Overlay 맥락 없음
                        ↓
         [ 미해결 문제 ]
  Overlay-aware cross-layer context를 결합하여
  East-West Lateral Movement를 탐지하는 연구
```

이 갭을 채우는 것이 본 연구의 존재 이유다.

---

## 5. Proposed Approach

### 5.1 eBPF가 해결책인 이유

eBPF는 커널 내부에서 사용자 정의 프로그램을 안전하게 실행할 수 있는 기술이다. 이 특성 덕분에 세 레이어의 정보를 **단일 커널 이벤트로 결합**하는 것이 가능하다.

```
[ eBPF Hook 위치 ]

tc (traffic control) hook        ← XDP hook이 아닌 tc를 사용하는 이유:
 └─ outer packet (node IP) 포착     XDP는 SKB 할당 이전 단계라 VXLAN inner header
 └─ VXLAN 헤더 파싱 → inner packet (pod IP) 추출   파싱이 제한적이며, tc는 SKB 완전 접근이 가능

kprobe / tracepoint
 └─ tcp_connect, sys_connect 이벤트
 └─ pid, process name, container namespace ID 포착

eBPF Map (공유 메모리)
 └─ network event + process event 를 pid/netns 기준으로 join
 └─ 단일 이벤트 생성:
    { outer_src, outer_dst, inner_src, inner_dst,
      pod_name, namespace, pid, process_name, timestamp }
```

기존 유저스페이스 도구는 이 결합이 불가능하다. 커널을 거친 뒤 각각의 인터페이스(netlink, /proc)에서 따로 수집하면 이미 맥락이 분리되어 있기 때문이다.

### 5.2 Cross-layer Correlation이 탐지를 가능하게 하는 이유

단순 flow 정보로는 다음을 구별할 수 없다.

```
[정상 트래픽]
backend-pod (pid=100, comm="node") → db-pod:5432

[Lateral Movement]
compromised-pod (pid=2341, comm="bash") → db-pod:5432
```

IP와 포트는 동일하다. 그러나 process context와 namespace context를 함께 보면 즉시 이상 행위를 식별할 수 있다.

이것이 cross-layer visibility가 탐지의 핵심 전제가 되는 이유다.

---

## 6. Comparison: Related Work vs. Proposed Research

| 구분 | 기존 eBPF/Cilium 연구 | 기존 보안 도구 | 본 연구 |
|------|----------------------|--------------|--------|
| 주요 목적 | 성능, 정책, observability | runtime 이상 탐지 | Overlay-aware lateral movement 탐지 |
| 관측 범위 | flow 또는 syscall 중 하나 | syscall 또는 flow 중 하나 | outer + inner + process 통합 |
| Overlay 인식 | 네트워킹 구현 관점 | 미지원 | 보안 탐지 관점에서 inner/outer 결합 |
| 공격 탐지 | 정책 위반 또는 단순 이벤트 | rule 기반 단일 이벤트 | 서비스 그래프 기반 흐름 이상 탐지 |
| 데이터셋 | 성능 실험 또는 flow 관측 | 전통 IDS 데이터셋 | Kubernetes Overlay 자체 데이터셋 |
| 공격 흐름 재구성 | 불가 | 불가 | 가능 (cross-layer correlation) |

---

## 7. Contributions

### Contribution 1. Cross-layer Correlation 메커니즘

eBPF를 활용하여 outer(node), inner(pod), process 세 레이어의 정보를 단일 이벤트로 결합하는 correlation 파이프라인을 설계한다. 이는 기존 어떤 도구도 제공하지 않는 구조다.

### Contribution 2. Overlay-aware Lateral Movement 탐지

단순 이상 행위 탐지가 아니라 **서비스 의존 그래프(service dependency graph)** 를 기준으로, 정상 graph에 없는 edge를 lateral movement로 판단하는 탐지 모델을 제시한다.

탐지 대상 시나리오:

| 시나리오 | 설명 |
|---------|------|
| Pod Network Scan | 비정상 프로세스가 cluster 내부 IP 대역을 탐색 |
| Port Scan | 특정 Pod의 port를 반복 탐색 |
| Namespace Traversal | 서비스 그래프에 없는 namespace 간 접근 |
| Abnormal Direct Access | frontend가 DB에 직접 접근 (backend 우회) |
| Service Discovery Abuse | 내부 DNS를 통한 서비스 열거 |

### Contribution 3. Kubernetes Overlay Dataset

기존 공개 데이터셋이 Kubernetes Overlay 맥락을 반영하지 못한다는 한계를 해결하기 위해, VXLAN 기반 실험 환경에서 정상/공격 트래픽을 직접 생성한 데이터셋을 구성한다.

수집 feature:

- Flow: src/dst IP, port, protocol, direction
- Kubernetes: pod, namespace, service
- Process: pid, process name, command, container ID
- Overlay: outer node IP, inner pod IP, VNI
- Behavior: connection count, unique dst count, namespace cross count, fanout score

### Contribution 4. Baseline Comparison and Evaluation

| Baseline | 사용 정보 |
|---------|---------|
| Flow-only | IP, port, protocol |
| K8s Metadata | flow + pod, namespace |
| **본 연구 (제안)** | flow + pod + process + overlay context |

세 방식의 탐지율, 오탐률, 공격 흐름 설명력을 비교하여 cross-layer context의 탐지 기여도를 정량적으로 검증한다.

---

## 8. 요약(논문에 넣어본다 생각하고 작성)

> eBPF와 Cilium은 Kubernetes 환경에서 고성능 네트워킹과 보안 정책 적용을 가능하게 하는 핵심 기술로 연구되어 왔다. 특히 Cilium은 iptables 기반 처리 방식의 한계를 완화하고, Hubble을 통해 서비스 간 flow 가시성을 제공한다. Falco, Tetragon 등의 eBPF 기반 보안 도구 역시 syscall 및 네트워크 이벤트 기반 이상 탐지를 제공한다. 그러나 기존 연구들은 공통적으로 다음 한계를 가진다. 첫째, VXLAN 기반 Overlay Network 환경에서 outer(node) 맥락과 inner(pod) 맥락을 단일 이벤트로 결합하지 못한다. 둘째, 네트워크 이벤트와 process context의 cross-layer correlation이 부재하다. 셋째, 서비스 의존 그래프를 기준으로 East-West Lateral Movement를 판단하는 탐지 모델을 제시하지 않는다. 본 연구는 이 갭을 해결하기 위해 eBPF 기반 cross-layer visibility reconstruction을 설계하고, 이를 통해 Kubernetes Overlay 환경에서 발생하는 lateral movement를 탐지하는 방법을 제안한다.

---

## 9. Dataset 설계 및 연구 방향

---

### 9.1 실험 환경 구성

#### Kubernetes 클러스터

| 항목 | 선택 | 이유 |
|------|------|------|
| 클러스터 도구 | **kind** (Kubernetes in Docker) | 멀티노드 구성이 쉽고, VXLAN cross-node 트래픽을 로컬에서 재현 가능 |
| 노드 구성 | control-plane × 1, worker × 2 | cross-node 트래픽(pod_A on node-1 → pod_B on node-2) 발생 필수 |
| CNI | **Flannel (VXLAN 모드)** | VXLAN encapsulation이 가장 직접적으로 드러남; VNI 기본값 1로 고정 |
| 대안 CNI | Calico (VXLAN 모드) | Flannel 결과 재현성 검증용 |

#### 샘플 애플리케이션

**GCP Online Boutique** (오픈소스 마이크로서비스 데모)를 기반 워크로드로 선택한다.

- 11개 마이크로서비스가 명확한 서비스 의존 그래프를 형성
- gRPC + HTTP 혼합 트래픽으로 실제 환경과 유사
- 서비스 간 의존 관계가 문서화되어 있어 **ground truth graph** 구성이 용이

```
[서비스 의존 그래프 — 정상 통신만 허용되는 edge]
frontend          → productcatalogservice, cartservice, currencyservice,
                    shippingservice, checkoutservice, recommendationservice
checkoutservice   → paymentservice, emailservice, shippingservice,
                    productcatalogservice, cartservice, currencyservice
cartservice       → redis
recommendationservice → productcatalogservice
```

이 그래프에 없는 edge는 모두 **이상 통신**으로 간주한다.

---

### 9.2 자체 데이터셋 설계

Section 3.3에서 확인했듯, 기존 공개 IDS 데이터셋(CICIDS2017, NSL-KDD, UNSW-NB15)은 Kubernetes Overlay 맥락을 반영하지 못한다. 따라서 본 연구는 다음과 같이 자체 데이터셋을 설계한다.

#### 수집 feature 전체 목록

| 카테고리 | feature | 설명 |
|----------|---------|------|
| **Outer (노드 레벨)** | `outer_src_ip` | VXLAN outer 출발지 노드 IP |
| | `outer_dst_ip` | VXLAN outer 목적지 노드 IP |
| | `vxlan_vni` | VXLAN Network Identifier |
| | `outer_ttl` | outer 패킷 TTL |
| | `outer_packet_len` | outer 패킷 전체 길이 |
| **Inner (Pod 레벨)** | `inner_src_ip` | pod 출발지 IP |
| | `inner_dst_ip` | pod 목적지 IP |
| | `inner_src_port` | 출발지 포트 |
| | `inner_dst_port` | 목적지 포트 |
| | `inner_protocol` | TCP / UDP |
| | `inner_payload_len` | inner 페이로드 길이 |
| **Process (커널 레벨)** | `pid` | 연결을 생성한 프로세스 ID |
| | `ppid` | 부모 프로세스 ID |
| | `process_name` | comm (예: node, python3, bash) |
| | `cmdline` | 명령줄 인수 (최대 128자) |
| | `uid` / `gid` | 프로세스 실행 권한 |
| | `container_id` | cgroup path에서 추출한 컨테이너 ID |
| **K8s 메타데이터** | `src_pod_name` | 출발지 Pod 이름 |
| | `src_namespace` | 출발지 Namespace |
| | `src_node` | 출발지 노드 이름 |
| | `dst_pod_name` | 목적지 Pod 이름 |
| | `dst_namespace` | 목적지 Namespace |
| | `dst_service` | 목적지 Service 이름 |
| **행위 feature (파생)** | `conn_rate` | 단위 시간당 연결 횟수 |
| | `unique_dst_count` | 단위 시간 내 고유 목적지 IP 수 |
| | `unique_dst_port_count` | 고유 목적지 포트 수 |
| | `cross_namespace_flag` | Namespace 경계 횡단 여부 (bool) |
| | `fanout_score` | unique_dst / conn_rate (분산도) |
| | `port_entropy` | 목적지 포트 분포 엔트로피 |
| **레이블** | `label` | `normal` / `pod_scan` / `port_scan` / `ns_traversal` / `db_direct` / `dns_enum` |
| | `attack_tool` | 공격에 사용한 도구 (레이블링용) |

#### 수집 파이프라인

```
eBPF tc hook (host NIC)
  └─ outer IP 포착 + VXLAN 파싱 → inner IP/port 추출
       ↓
eBPF kprobe (tcp_connect / sys_connect)
  └─ pid, ppid, process_name, container_id, uid 포착
       ↓
eBPF Map (pid + netns 기준 join)
  └─ 단일 raw event 생성
       ↓
Userspace collector (Go / Python)
  └─ K8s API 조회로 pod_name, namespace, node 매핑
  └─ 행위 feature 집계 (60s sliding window)
  └─ CSV / Parquet 저장
```

#### 레이블링 방식

- **정상 구간**: 24시간 이상 Online Boutique 정상 트래픽 + [Locust](https://locust.io/) 부하 생성
- **공격 구간**: 각 시나리오 실행 전후에 `start_time` / `end_time` 기록 → timestamp 기반 자동 레이블 부착
- 정상:공격 비율 목표 ≥ 10:1 (실제 환경 반영)

---

### 9.3 공격 시나리오 재현 방법

모든 시나리오는 **침해된 Pod 하나에서 시작**하는 상황을 가정한다. 공격자는 `kubectl exec` 또는 웹쉘로 Pod 내부에 진입한 상태.

#### 시나리오 1: Pod Network Scan

```bash
# compromised-pod 내부에서 실행
kubectl exec -it compromised-pod -- bash
$ nmap -sn 10.244.0.0/16          # 전체 pod CIDR ICMP 스캔
$ masscan 10.244.0.0/16 -p0-65535  # 빠른 full-port 스캔 (옵션)
```

탐지 신호: `unique_dst_count` 급증, `conn_rate` 폭증, `cross_namespace_flag=True`, `process_name=nmap/masscan`

#### 시나리오 2: Port Scan

```bash
$ nmap -p 1-65535 10.244.2.8   # 특정 pod 대상 포트 스캔
```

탐지 신호: `unique_dst_port_count` 폭증, `port_entropy` 최대, 단시간 내 SYN-RST 반복

#### 시나리오 3: Namespace Traversal

```bash
# default namespace의 pod에서 kube-system namespace 서비스 접근
$ curl http://kube-dns.kube-system.svc.cluster.local
$ curl http://10.96.0.10:9153/metrics   # Prometheus metrics 탈취 시도
```

탐지 신호: `cross_namespace_flag=True`, 서비스 의존 그래프에 없는 edge, `process_name=curl/wget`

#### 시나리오 4: Abnormal Direct DB Access (backend 우회)

```bash
# frontend pod에서 직접 DB 접속 (정상적으로는 frontend→backend→DB여야 함)
$ python3 -c "import psycopg2; psycopg2.connect(host='10.244.2.8', port=5432, ...)"
# 또는
$ redis-cli -h 10.244.1.9 -p 6379
```

탐지 신호: `(src=frontend, dst=redis, dst_port=6379)` — 서비스 그래프에 없는 edge; `process_name=python3` 이 frontend pod에서 DB 포트 접근

#### 시나리오 5: Service Discovery Abuse (DNS Enumeration)

```bash
$ curl http://kubernetes.default.svc/api/v1/services    # K8s API 서비스 목록
$ for ns in $(cat /etc/resolv.conf); do
    dig @10.96.0.10 *.${ns}.svc.cluster.local;          # DNS enumeration
  done
```

탐지 신호: DNS 쿼리 급증, 다수의 NXDOMAIN, kubernetes API server 직접 접근

---

### 9.4 탐지 모델 방향

#### 서비스 의존 그래프 (Service Dependency Graph, SDG)

정상 트래픽 관측 구간 동안 다음 형식으로 그래프를 학습한다.

```
노드: (namespace, pod_type, process_name)
엣지: (src_node, dst_node, dst_port, protocol)

정상 edge 예시:
  (default, frontend, node)      → (default, cartservice, grpc_server)   : 7070/TCP
  (default, checkoutservice, *)  → (default, redis, redis-server)         : 6379/TCP
```

탐지 기준 (우선순위 순):

| 우선순위 | 탐지 규칙 | 탐지 대상 시나리오 |
|---------|-----------|-----------------|
| 1 | SDG에 없는 `(src, dst, port)` edge | Namespace Traversal, DB Direct Access |
| 2 | `process_name`이 해당 pod에서 예상되지 않는 프로세스 | 모든 시나리오 |
| 3 | `fanout_score > threshold` | Pod Network Scan |
| 4 | `unique_dst_port_count > threshold` in time window | Port Scan |
| 5 | DNS query rate 급증 + NXDOMAIN 비율 | Service Discovery Abuse |

#### 탐지 알고리즘 선택지

| 방식 | 알고리즘 | 특성 |
|------|---------|------|
| **Rule-based (Phase 1)** | SDG 엣지 룩업 | 빠른 탐지, 오탐 낮음, 새 공격 패턴에 취약 |
| **Anomaly (Phase 2)** | Isolation Forest, LOF | 레이블 없이 행위 이상 탐지 가능 |
| **Supervised (Phase 2)** | Random Forest, XGBoost | Feature importance로 cross-layer 기여도 분석 가능 |
| **Graph-based (Phase 3, 선택)** | GNN (GraphSAGE, GAT) | 그래프 구조 이상 탐지, 계산 비용 높음 |

Phase 1 (rule-based) + Phase 2 (supervised) 조합을 주 방법론으로 채택하고, GNN은 비교 실험으로 포함한다.

---

### 9.5 평가 지표 및 Baseline 비교

#### 평가 지표

| 지표 | 의미 |
|------|------|
| **Precision** | 탐지된 이벤트 중 실제 공격 비율 (오탐 관련) |
| **Recall** | 실제 공격 중 탐지된 비율 (미탐 관련) |
| **F1-score** | Precision/Recall 조화 평균 |
| **FPR** (False Positive Rate) | 정상 트래픽 중 공격으로 잘못 판단한 비율 |
| **Detection Latency** | 공격 발생 → 이벤트 탐지까지 걸리는 시간 (ms) |
| **eBPF Overhead** | 파이프라인 활성화 시 CPU/Memory 사용 증가율 |

#### Ablation Study — Cross-layer Context의 탐지 기여도

| Baseline | 사용 feature | 목적 |
|---------|-------------|------|
| **Flow-only** | `inner_src_ip, inner_dst_ip, port, protocol` | 전통 IDS 방식과 동일 조건 |
| **K8s Metadata** | Flow + `pod_name, namespace, service` | K8s 인지 IDS와 동일 조건 |
| **본 연구 (제안)** | Flow + K8s + `outer_ip, process, pid, fanout` | Cross-layer 전체 |

세 방식의 F1, FPR, 공격 흐름 설명력을 시나리오별로 비교하여 각 레이어 추가의 탐지 기여도를 정량화한다.

---

### 9.6 연구 단계별 계획

```
Phase 1 — eBPF 파이프라인 구현 (설계 + 구현)
  ├─ kind 클러스터 구성 + Flannel VXLAN 확인
  ├─ tc hook으로 outer/VXLAN/inner 패킷 파싱 구현
  ├─ kprobe (tcp_connect)로 pid/process/netns 포착 구현
  ├─ eBPF Map join → 단일 이벤트 출력 확인
  └─ 출력 형식 검증: outer_src, outer_dst, inner_src, inner_dst, pid, comm, namespace

Phase 2 — 데이터 수집 (실험 환경 구축 + 트래픽 생성)
  ├─ Online Boutique 배포 + Locust 부하 생성 (정상 24시간)
  ├─ 공격 시나리오 5종 순차 재현 (각 30분 이상)
  ├─ K8s API 메타데이터 매핑 + 행위 feature 집계
  └─ 데이터셋 완성: CSV/Parquet, 레이블 포함

Phase 3 — 탐지 모델 구현 (서비스 그래프 + 알고리즘)
  ├─ 정상 구간 데이터로 SDG 자동 구성
  ├─ Rule-based 탐지기 구현 (SDG edge lookup + process check)
  ├─ Supervised 모델 학습 (Random Forest / XGBoost)
  └─ Ablation study: feature 그룹별 탐지율 비교

Phase 4 — 평가 및 분석 (논문 작성 대상)
  ├─ 시나리오별 Precision/Recall/F1/FPR 측정
  ├─ Baseline 3종 비교 (flow-only, k8s, cross-layer)
  ├─ Detection latency 측정 (eBPF event → alert)
  ├─ eBPF 오버헤드 측정 (without/with pipeline)
  └─ 결과 해석: cross-layer context가 어떤 시나리오에서 결정적인가
```

---

## 10. References

### eBPF 커널 보안 / 프로세스-네트워크 상관관계

1. He, Y. et al., "Cross Container Attacks: The Bewildered eBPF on Clouds," *USENIX Security Symposium*, 2023.
   [[PDF]](https://www.usenix.org/system/files/usenixsecurity23-he.pdf)
   — eBPF가 컨테이너 namespace를 우회하여 cross-host 공격 벡터가 될 수 있음을 증명; eBPF 커널 수준 권한 특성 논증

2. Fournier, G. et al., "Process level network security monitoring & enforcement with eBPF," *SSTIC*, 2020.
   [[PDF]](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/process_level_network_security_monitoring_and_enfo/SSTIC2020-Article-process_level_network_security_monitoring_and_enforcement_with_ebpf-fournier_Cuzi8wu.pdf)
   — process-network 레벨 eBPF 모니터링 초기 연구; pid/netns 기반 상관관계 기법 원형

3. Bernal Bernabé, J. et al., "Combining System Visibility and Security Using eBPF," *ITASEC*, 2019.
   [[PDF]](https://luca.ntop.org/ITASEC2019.pdf)
   — 시스템+네트워크 메타데이터 상관관계를 통한 보안 관측성 접근

4. Coppola, M. et al., "eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation," *arXiv:2511.18155*, 2025.
   [[arXiv]](https://arxiv.org/abs/2511.18155)
   — UID/PID/cgroup/namespace를 결합한 eBPF 이벤트 생성; cgroup-aware 필터링으로 컨테이너 맥락 귀속

5. Zhang, R. et al., "eBPF-Guard: A Detection Method for Container Escape via Multi-level Monitoring," *Empirical Software Engineering*, Springer, 2025.
   [[Springer]](https://link.springer.com/article/10.1007/s10664-025-10784-1)
   — kernel namespace+cgroup 기반 cross-host container interaction 모니터링 체인 구성

---

### eBPF 기반 보안 도구 비교 (Falco / Tetragon / Tracee)

6. Hamm, L. et al., "Comparative Analysis of eBPF-Based Runtime Security Monitoring," *SCITEPRESS*, 2025.
   [[PDF]](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
   — Falco, Tetragon, Tracee를 Container Escape/DoS/Cryptomining 기준으로 탐지 성능 및 자원 사용 비교; 도구별 한계 체계적 분석

7. AccuKnox, "Container Runtime Security Tooling Comparison," *Technical Report*, 2023.
   [[PDF]](https://www.accuknox.com/wp-content/uploads/Container_Runtime_Security_Tooling.pdf)
   — Falco/Tetragon/KubeArmor 관측 범위, 정책 지원, 오버헤드 실용적 비교

---

### Kubernetes 보안 / Lateral Movement

8. Brignoli, N. et al., "KubeHound: Identifying Attack Paths in Kubernetes Clusters," *Datadog Security Labs*, 2023.
   [[Web]](https://securitylabs.datadoghq.com/articles/kubehound-identify-kubernetes-attack-paths/)
   — 공격 그래프(attack graph) 기반 Kubernetes lateral movement 경로 자동 분석; 서비스 의존 그래프와 연결

9. Lin, Y. et al., "ShadowKube: Enhancing Kubernetes Security with Behavioral Monitoring and Honeypot Integration," *Cybersecurity*, Springer Nature, 2025.
   [[Springer]](https://link.springer.com/article/10.1186/s42400-025-00372-7)
   — Kubernetes 행위 기반 베이스라인 탐지 + shadow honeypot 통합

10. Tigera, "Kubernetes Security: Lateral Movement Detection and Defense," *Technical Blog*, 2023.
    [[Web]](https://www.tigera.io/blog/kubernetes-security-lateral-movement-detection-and-defense/)
    — East-West 트래픽 기반 lateral movement 탐지 실용적 분석 및 eBPF 기반 대응 방안

---

### eBPF 패킷 처리 / VXLAN 프로토콜

11. Vieira, M. et al., "Fast Packet Processing with eBPF and XDP: Concepts, Code, and Applications," *UFMG Technical Report*, 2020.
    [[PDF]](https://homepages.dcc.ufmg.br/~mmvieira/so/papers/Fast_Packet_Processing_with_eBPF_and_XDP.pdf)
    — XDP/tc hook 동작 원리 및 패킷 파싱 기법; XDP vs tc 비교 (SKB 접근 시점 차이)

12. Mahalingam, M. et al., "RFC 7348 – Virtual eXtensible Local Area Network (VXLAN)," *IETF*, 2014.
    [[RFC]](https://datatracker.ietf.org/doc/html/rfc7348)
    — VXLAN 프로토콜 공식 표준; outer/inner 헤더 구조 정의

13. Cilium Project, "Introduction to eBPF in Cilium," *Official Documentation*, 2024.
    [[Docs]](https://docs.cilium.io/en/stable/concepts/ebpf/intro/)
    — tc hook, eBPF Map, Kubernetes CNI 구현 원리; Hubble flow record 구조

---

### IDS 데이터셋 (기존 데이터셋의 한계 논증)

14. Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A.A., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," *ICISSP*, 2018.
    [[PDF]](https://www.scitepress.org/papers/2018/66398/66398.pdf) | [DOI: 10.5220/0006639801080116](https://www.paperdigest.org/paper/?paper_id=doi.org_10.5220_0006639801080116) | [[Dataset]](https://www.unb.ca/cic/datasets/ids-2017.html)
    — CICIDS2017 원논문; 전통 네트워크 기반 2.5M 레코드, container context 없음

15. Moustafa, N., Slay, J., "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems," *MilCIS*, 2015.
    [[Dataset]](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
    — UNSW-NB15 원논문; 9가지 공격 유형, Kubernetes/Pod 맥락 미반영

16. Tavallaee, M. et al., "A Detailed Analysis of the KDD CUP 99 Data Set," *IEEE CISDA*, 2009.
    [[IEEE]](https://ieeexplore.ieee.org/document/5356528/) | [[PDF]](https://www.ee.torontomu.ca/~bagheri/papers/cisda.pdf) | [[Dataset]](https://www.unb.ca/cic/datasets/nsl.html)
    — NSL-KDD 원논문; 전통 IDS 벤치마크, East-West microservice 트래픽 미반영



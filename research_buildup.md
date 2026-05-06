# Kubernetes Overlay Network에서 eBPF 기반 Cross-layer Visibility를 활용한 Lateral Movement 탐지

---

## 0. Overview

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

현재 모니터링 도구들은 이 세 레이어를 **각각 따로** 본다.

| 관측 위치 | 볼 수 있는 정보 | 볼 수 없는 정보 |
|----------|---------------|---------------|
| NIC 수준 (outer) | node IP | pod IP, process |
| Pod 내부 (inner) | pod IP, port | node IP, 캡슐화 맥락 |
| 커널 syscall | process, pid | 어느 pod인지, 네트워크 목적지 |

결과적으로 다음 질문에 아무도 답하지 못한다.

> "pod_A 내부의 python3 프로세스(pid 1234)가 node_B의 pod_B에 있는 MySQL(3306)에 접근했는가?"

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

즉, 기존 IDS 연구의 방법론을 그대로 Kubernetes Overlay 환경에 적용하면 **탐지에 필요한 핵심 정보가 처음부터 빠져있다**.

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

### 5.1 eBPF가 유일한 해결책인 이유

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

## 8. Related Work Transition Paragraph

> eBPF와 Cilium은 Kubernetes 환경에서 고성능 네트워킹과 보안 정책 적용을 가능하게 하는 핵심 기술로 연구되어 왔다. 특히 Cilium은 iptables 기반 처리 방식의 한계를 완화하고, Hubble을 통해 서비스 간 flow 가시성을 제공한다. Falco, Tetragon 등의 eBPF 기반 보안 도구 역시 syscall 및 네트워크 이벤트 기반 이상 탐지를 제공한다. 그러나 기존 연구들은 공통적으로 다음 한계를 가진다. 첫째, VXLAN 기반 Overlay Network 환경에서 outer(node) 맥락과 inner(pod) 맥락을 단일 이벤트로 결합하지 못한다. 둘째, 네트워크 이벤트와 process context의 cross-layer correlation이 부재하다. 셋째, 서비스 의존 그래프를 기준으로 East-West Lateral Movement를 판단하는 탐지 모델을 제시하지 않는다. 본 연구는 이 갭을 해결하기 위해 eBPF 기반 cross-layer visibility reconstruction을 설계하고, 이를 통해 Kubernetes Overlay 환경에서 발생하는 lateral movement를 탐지하는 방법을 제안한다.

---

## 10. References

### eBPF 커널 보안 / 프로세스-네트워크 상관관계

1. He, Y. et al., "Cross Container Attacks: The Bewildered eBPF on Clouds," *USENIX Security Symposium*, 2023.
   - eBPF가 컨테이너 namespace를 우회하여 cross-host 공격 벡터가 될 수 있음을 증명; eBPF의 커널 수준 권한 특성 논증

2. Fournier, G. et al., "Process level network security monitoring & enforcement with eBPF," *SSTIC*, 2020.
   - process-network 레벨 eBPF 모니터링 초기 연구; pid/netns 기반 상관관계 기법 원형

3. Bernal Bernabé, J. et al., "Combining System Visibility and Security Using eBPF," *ITASEC*, 2019.
   - 시스템+네트워크 메타데이터 상관관계를 통한 보안 관측성 접근

4. Coppola, M. et al., "eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation," *arXiv:2511.18155*, 2025.
   - UID/PID/cgroup/namespace를 결합한 eBPF 이벤트 생성; cgroup-aware 필터링으로 컨테이너 맥락 귀속

5. Zhang, R. et al., "eBPF-Guard: A Detection Method for Container Escape via Multi-level Monitoring," *Empirical Software Engineering*, Springer, 2025.
   - kernel namespace+cgroup 기반 cross-host container interaction 모니터링 체인 구성

---

### eBPF 기반 보안 도구 비교 (Falco / Tetragon / Tracee)

6. Hamm, L. et al., "Comparative Analysis of eBPF-Based Runtime Security Monitoring," *SCITEPRESS*, 2025.
   - Falco, Tetragon, Tracee를 Container Escape/DoS/Cryptomining 기준으로 탐지 성능 및 자원 사용 비교; 도구별 한계 체계적 분석

7. AccuKnox, "Container Runtime Security Tooling Comparison," *Technical Report*, 2023.
   - Falco/Tetragon/KubeArmor 관측 범위, 정책 지원, 오버헤드 실용적 비교

---

### Kubernetes 보안 / Lateral Movement

8. Brignoli, N. et al., "KubeHound: Identifying Attack Paths in Kubernetes Clusters," *Datadog Security Labs*, 2023.
   - 공격 그래프(attack graph) 기반 Kubernetes lateral movement 경로 자동 분석; 서비스 의존 그래프와 연결

9. Lin, Y. et al., "ShadowKube: Enhancing Kubernetes Security with Behavioral Monitoring and Honeypot Integration," *Cybersecurity*, Springer Nature, 2025.
   - Kubernetes 행위 기반 베이스라인 탐지 + shadow honeypot 통합

10. Tigera, "Kubernetes Security: Lateral Movement Detection and Defense," *Technical Blog*, 2023.
    - East-West 트래픽 기반 lateral movement 탐지 실용적 분석 및 eBPF 기반 대응 방안

---

### eBPF 패킷 처리 / VXLAN 프로토콜

11. Vieira, M. et al., "Fast Packet Processing with eBPF and XDP: Concepts, Code, and Applications," *UFMG Technical Report*, 2020.
    - XDP/tc hook 동작 원리 및 패킷 파싱 기법; XDP vs tc 비교 (SKB 접근 시점 차이)

12. Mahalingam, M. et al., "RFC 7348 – Virtual eXtensible Local Area Network (VXLAN): A Framework for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks," *IETF*, 2014.
    - VXLAN 프로토콜 공식 표준; outer/inner 헤더 구조 정의

13. Cilium Project, "Introduction to eBPF in Cilium," *Official Documentation*, 2024.
    - tc hook, eBPF Map, Kubernetes CNI 구현 원리; Hubble flow record 구조

---

### IDS 데이터셋 (기존 데이터셋의 한계 논증)

14. Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A.A., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," *ICISSP*, 2018.
    - CICIDS2017 데이터셋 원논문; 전통 네트워크 환경 기반 2.5M 레코드, container context 없음

15. Moustafa, N., Slay, J., "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems," *MilCIS*, 2015.
    - UNSW-NB15 데이터셋 원논문; 9가지 공격 유형, Kubernetes/Pod 맥락 미반영

16. Tavallaee, M. et al., "A Detailed Analysis of the KDD CUP 99 Data Set," *IEEE CISDA*, 2009.
    - NSL-KDD 데이터셋 원논문; 전통 IDS 벤치마크, East-West microservice 트래픽 미반영

---

## 9. Executive Summary

기존 eBPF와 Cilium 관련 연구는 클라우드 네이티브 환경에서 고성능 네트워킹, 네트워크 정책 적용, service mesh 대체, observability 제공에 초점을 맞추고 있습니다. Falco, Tetragon과 같은 보안 도구 역시 syscall 또는 flow를 관측하지만, VXLAN Overlay로 인해 분리되는 outer(node), inner(pod), process 세 레이어의 정보를 단일 이벤트로 결합하는 기능은 제공하지 않습니다. 이 cross-layer correlation이 부재하면, 침해된 Pod에서 발생하는 Lateral Movement가 정상 서비스 트래픽과 동일하게 보여 탐지가 불가능합니다. 본 연구는 eBPF를 활용하여 이 세 레이어를 커널 수준에서 결합하고, 서비스 의존 그래프를 기준으로 East-West Lateral Movement를 탐지하는 방법을 제안합니다. 기존 공개 IDS 데이터셋은 Kubernetes Overlay 맥락을 반영하지 못하므로, 직접 실험 환경을 구축하여 정상 및 공격 트래픽을 생성하고 평가할 계획입니다.

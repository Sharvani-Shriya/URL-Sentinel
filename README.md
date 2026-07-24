# URLSentinel: A Latency-Aware Hybrid Escalation Architecture for Malicious URL Detection with Regional Retrieval-Augmented Reasoning

------------------------------------------------------------------------

## 1. Introduction

### 1.1 Motivation and Global Threat Landscape

Global digital connectivity continues to expand at an unprecedented
pace. According to the International Telecommunication Union (ITU) [1],
approximately six billion people---representing nearly three-quarters of
the global population---are now active internet users, reflecting an
increase of more than 240 million connected individuals year-over-year.
This rapid expansion of the digital footprint has been accompanied by a
proportional rise in the scale, velocity, and complexity of
cyber-enabled threats.

The World Economic Forum (WEF) [2] reports that cyber-enabled fraud and
targeted phishing campaigns have, for the first time, overtaken
traditional ransomware as the leading operational concern for
organizations globally. Recent survey data indicates that over $73\%$ of
polled organizations experienced network-level fraud events, with social
engineering vectors---specifically phishing, smishing, and
vishing---cited as the primary entry mechanism by $62\%$ of affected
institutions. Because malicious hyperlinks serve as the foundational
delivery mechanism for credential harvesting, drive-by malware
downloads, and unauthorized access, inspectable Uniform Resource
Locators (URLs) remain one of the most critical and actionable points of
interception in enterprise security defense.

    +----------------------------------------------------------------------------------------------------+
    |                                  Malicious URL Detection Paradigm                                  |
    +----------------------------------------------------------------------------------------------------+
                                                      |
           +------------------------------------------+------------------------------------------+
           |                                          |                                          |
           v                                          v                                          v
    +-----------------------------+    +-----------------------------+    +-----------------------------+
    |    Static Blacklisting      |    |   Feature-Based ML Models   |    |    Agentic & RAG Systems    |
    | - Low latency lookups       |    | - High general accuracy     |    | - Dynamic live reasoning    |
    | - Zero-day blind spots      |    | - Static & regionally brittle|    | - Cost & latency prohibitive|
    +-----------------------------+    +-----------------------------+    +-----------------------------+

### 1.2 Limitations of Existing Detection Paradigms

Countermeasures against malicious URLs in the existing literature
primarily span three paradigms, each exhibiting structural limitations:

1.  **Static Blacklisting Systems:** Databases such as PhishTank [6] and
    Google Safe Browsing perform fast lookup matching against
    historically confirmed malicious domain repositories. While
    computationally efficient, these systems are inherently retroactive
    and fail to detect zero-day phishing domains, fast-flux networks, or
    dynamically generated URLs.

2.  **Feature-Based Machine Learning Classifiers:** Supervised learning
    models trained on lexical, host-based, content, and syntactic
    HTML/JS attributes generalize beyond static lists and represent the
    standard baseline in academic literature [3, 4]. However, these classifiers
    remain static post-deployment and suffer performance degradation under
    regional or domain distribution shifts. For example, empirical
    findings by Bat-Erdene et al. [5] demonstrated that while a 52-feature
    Gradient Boosting classifier achieves $99.87\%$ accuracy on standard
    global web datasets, its detection capabilities drop
    significantly---to $55\text{--}75\%$---when evaluated against
    localized regional domains (such as `.gov.mn` or `.edu.mn`
    infrastructure). Retraining these models or manually engineering
    bespoke feature sets for every underrepresented geographic region is
    computationally expensive and structurally unscalable.

3.  **Agentic LLMs and Retrieval-Augmented Generation (RAG):** Emerging
    Large Language Model (LLM) agents can incorporate live network
    context, inspect dynamic page behaviors, and generate human-readable
    threat explanations [7, 8]. However, their inference latency
    ($>1500\text{ ms}$) and API computational overhead render them
    cost-prohibitive as primary screening filters for enterprise-scale,
    high-throughput web traffic.

### 1.3 Key Contributions

To address the trilemma of **throughput**, **regional adaptability**,
and **explainability**, this work introduces **URLSentinel**, a
latency-aware, 5-tier hybrid escalation framework. URLSentinel routes the
vast majority of incoming web traffic through a fast offline lexical
classifier while dynamically escalating ambiguous or out-of-distribution
samples through progressive verification tiers.

The primary contributions of this paper are summarized as follows:

-   **Latency-Aware Escalation Architecture:** We propose a 5-tier
    pipeline that processes low-risk and high-confidence URLs via a fast
    offline lexical ML model ($<5\text{ ms}$) while reserving expensive
    live forensics, regional RAG retrieval, and rule-grounded reasoning
    for genuinely ambiguous samples:
    1. *Tier 1:* Fast Offline Lexical Machine Learning Classifier
    2. *Tier 2:* Dynamic Live Forensics Engine (DNS, WHOIS, SSL Inspection)
    3. *Tier 3:* Regional RAG & Vector Knowledge Base
    4. *Tier 4:* Agentic LLM / Rule-Grounded Reasoning Engine
    5. *Tier 5:* Multi-Source Calibrated Decision Fusion Engine

-   **Region-Agnostic Adaptation via Retrieval:** Rather than manually
    crafting static, country-specific features for localized domains,
    URLSentinel incorporates localized threat context through a
    Retrieval-Augmented Knowledge Base, enabling non-intrusive
    adaptation to new geographic domains without model retraining.

-   **Domain-Grouped Evaluation Protocol:** We introduce a rigorous
    evaluation methodology that separates Top-Level Domains (TLDs) and
    Second-Level Domains (SLDs) between training and testing splits
    ($D_{\text{train}} \cap D_{\text{test}} = \emptyset$), eliminating
    domain memorization artifacts present in standard random row-level
    splits.

-   **Calibrated Multi-Source Decision Fusion:** We formulate a
    multi-tier fusion score combining prior model probabilities, live
    DNS/WHOIS indicators, vector alignment metrics, and rule-grounded
    reasoning weights into a unified confidence score with dynamic network fallback capabilities.

### 1.4 Paper Organization

The remainder of this paper is structured as follows. Section 2 reviews
related work in feature-based URL classification, regional domain
biases, and agentic LLM frameworks. Section 3 details the 5-tier
URLSentinel system architecture, feature groups, and decision fusion
formula. Section 4 outlines the experimental setup, dataset composition,
and the domain-grouped split protocol. Section 5 presents benchmark
results, latency analyses, and a tiered ablation study. Section 6
delivers a comparative discussion against prior baseline models. Section
7 discusses system limitations, and Section 8 concludes the paper with
future research directions.

------------------------------------------------------------------------

## 2. Related Work

    +----------------------------------------------------------------------------------------------------+
    |                                    Taxonomy of Related Approaches                                  |
    +----------------------------------------------------------------------------------------------------+
               |                                         |                                         |
               v                                         v                                         v
    +---------------------------+             +---------------------------+             +---------------------------+
    | Feature-Based ML Methods  |             | Regional & Domain Bias    |             | Agentic & RAG Frameworks  |
    | - Sahoo et al. Survey [3] |             | - Bat-Erdene et al. [5]   |             | - Live Context Ingestion  |
    | - Tian et al. Survey [4]  |             | - Static Rule Retraining  |             | - High Overhead & Latency |
    +---------------------------+             +---------------------------+             +---------------------------+

### 2.1 Taxonomy of Feature-Based Machine Learning

Machine learning approaches for malicious URL detection have evolved
from basic string heuristic checks to multi-modal feature extraction
pipelines. Taxonomies established by Sahoo et al. [3] and Tian et
al. [4] categorize features into five core groups:

1.  **Lexical Features:** Syntactic properties extracted directly from
    the URL string, including URL length, path depth, character entropy,
    digit counts, and special character ratios.

2.  **Host-Based Features:** Network-level characteristics, such as DNS
    A/AAAA record presence, WHOIS domain age, autonomous system numbers
    (ASN), and IP address hosting attributes.

3.  **Content-Based Features:** Properties obtained by downloading page
    responses, including iframe presence, script execution triggers, and
    redirection chain counts.

4.  **Anomaly-Based Features:** Structural anomalies, such as Punycode
    homograph obfuscation, mixed character sets, and protocol
    mismatches.

5.  **HTML/JavaScript Features:** Document Object Model (DOM) mutation
    rates, inline script ratios, and local storage operation counts.

While supervised algorithms---including Random Forests (RF), Support
Vector Machines (SVM), and Gradient Boosting (GB)---achieve reported
benchmark accuracies above $98\%$ on standard collections like PhishTank
and Kaggle, these models rely on the assumption that training and
deployment feature distributions are identical. When exposed to novel
domain structures or regional web traffic, these static classifiers
experience notable degradation in accuracy.

### 2.2 Regional Bias and the Base Study Benchmark

The vulnerability of supervised models under domain distribution shifts
is highlighted in the study by Bat-Erdene et al. [5]. In their baseline
setup, the authors compiled a corpus of 516,278 global URLs (292,161
benign and 224,117 malicious) alongside a localized dataset of 13,019
Mongolian benign URLs (`.gov.mn` and `.edu.mn`).

    +----------------------------------------------------------------------------------------------------+
    |                           Progression of Baseline Feature Sets [5]                                 |
    +----------------------------------------------------------------------------------------------------+
    |                                                                                                    |
    |  [21 Lexical Features] -------------> 89.85% Accuracy (Foreign Dataset)                            |
    |          |                                                                                         |
    |          v                                                                                         |
    |  [36 Multi-Modal Features] ---------> 97.57% Accuracy (Foreign) / 57.56% Accuracy (Mongolian)      |
    |          |                                                                                         |
    |          v                                                                                         |
    |  [52 Feature Set] ------------------> 99.81% Accuracy (Foreign) / 56.86% Accuracy (Mongolian)      |
    |          |                                                                                         |
    |          v (Removed 18 web features + Added 16 Mongolian-specific static features)                   |
    |  [50 Final Features] ---------------> 99.87% Accuracy (Foreign) / 75.15% Accuracy (Mongolian)      |
    |                                                                                                    |
    +----------------------------------------------------------------------------------------------------+

Their experimental progression demonstrated clear performance patterns:

-   **Initial Lexical Baseline (21 Features):** Achieved an accuracy of
    $89.85\%$ using a Random Forest model on foreign datasets.

-   **Expansion to 36 Features:** Incorporating domain and content
    attributes raised foreign dataset accuracy to $97.57\%$. However,
    when tested on the Mongolian dataset, model accuracy dropped to
    $57.56\%$.

-   **Expansion to 52 Features:** Increased global foreign accuracy to
    $99.81\%$ via Gradient Boosting, but regional Mongolian domain
    accuracy degraded further to $56.86\%$.

-   **Feature Removal and Regional Engineering (50 Final Features):**
    The authors eliminated 18 web access features returning zero values
    due to server unreachability and added 16 static, region-specific
    features (e.g., `is_gov_domain`, `has_mongolian_region`,
    `is_ministerial_domain`). This static adjustment raised regional
    Mongolian accuracy to $75.15\%$.

While effective for a specific target region, this manual feature
engineering approach exhibits critical limitations:

1.  **Unscalable Maintenance:** Engineering static binary indicators for
    every sovereign Top-Level Domain or institutional naming convention
    requires continuous human intervention.

2.  **Overfitting Risks:** Hardcoding domain structural prefixes trains
    models to associate safety with specific string tokens rather than
    learning intrinsic threat behaviors.

### 2.3 RAG and Agentic LLM Architectures in Cybersecurity

To overcome the rigidity of static machine learning, recent research has
explored Large Language Models (LLMs) and Retrieval-Augmented Generation
(RAG) for automated threat intelligence [7, 8]. RAG frameworks
dynamically query external knowledge bases---such as active domain
registries, threat feeds, and regional portal white-lists---injecting
relevant context into the LLM prompt without requiring model retraining
or feature re-engineering.

However, existing agentic security workflows apply LLM inference
indiscriminately to all incoming queries, incurring significant latency
($>1500\text{ ms}$) and operational costs. URLSentinel addresses this
operational bottleneck by positioning RAG and LLM reasoning engines as
late-stage escalation tiers, activating them exclusively when lower-cost
models express high uncertainty.

------------------------------------------------------------------------
